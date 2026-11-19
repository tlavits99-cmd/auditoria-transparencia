import asyncio, re, io, os, ipaddress, socket
from collections import deque
from datetime import datetime, date
from urllib.parse import urljoin, urlparse, urldefrag
import httpx
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from pypdf import PdfReader

APP_NAME = "Motor de Consulta - Auditoria da Transparência"
MAX_PAGES = int(os.getenv("MAX_PAGES", "55"))
MAX_DEPTH = int(os.getenv("MAX_DEPTH", "2"))
TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "18"))
USER_AGENT = os.getenv("USER_AGENT", "AuditoriaTransparenciaResearch/1.0 (public-information research)")
# For production, set ALLOWED_ORIGINS to a comma-separated list of exact HTML origins.
allowed = [x.strip() for x in os.getenv("ALLOWED_ORIGINS", "*").split(",") if x.strip()]
app = FastAPI(title=APP_NAME, version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed if allowed else ["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

TOPICS = {
 "atos": ["atos normativos","portaria","decreto","lei municipal","legislação"],
 "receita": ["receita","duodécimo","duodecimo","transferência financeira","transferencia financeira"],
 "despesa": ["despesa","empenho","liquidação","liquidacao","pagamento"],
 "convenios": ["convênio","convenio","convênios","convenios"],
 "rh": ["recursos humanos","folha de pagamento","estagiário","estagiario","terceirizado","concurso público","concurso publico"],
 "diarias": ["diária","diaria","diárias","diarias"],
 "licitacoes": ["licitação","licitacao","dispensa","pregão","pregao","ata de registro","licitantes sancionados"],
 "contratos": ["contrato","termo aditivo","aditivo","ordem cronológica","ordem cronologica"],
 "obras": ["obras","engenharia","execução de obras","execucao de obras"],
 "legislativo": ["legislativo","sessão","sessao","pauta","frequência parlamentar","frequencia parlamentar","projeto de lei","matéria","materia","comissões","comissoes"],
}
DATE_RE = re.compile(r'\b(?:0?[1-9]|[12]\d|3[01])[./-](?:0?[1-9]|1[0-2])[./-](?:20\d{2})\b|\b20\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b')
NUM_RE = re.compile(r'\b(?:Portaria|Decreto|Lei|Processo|Contrato|Dispensa|Pregão|Pregao|Parecer|Projeto(?:\s+de\s+Lei)?|Aditivo)\s*(?:n[º°.]?\s*)?[\w./-]{1,25}', re.I)

class AuditRequest(BaseModel):
    orgao: str = ""
    tipo: str = ""
    municipio: str = ""
    portal: HttpUrl
    data_referencia: str | None = None
    topicos: list[str] = []

def safe_public_url(url: str):
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("URL deve usar http ou https.")
    # Block localhost/private IP targets to prevent SSRF.
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(p.hostname))
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise ValueError("Endereço local ou privado não permitido.")
    except socket.gaierror:
        pass
    return url

def same_host(a, b):
    return urlparse(a).netloc.lower() == urlparse(b).netloc.lower()

def norm_url(u):
    return urldefrag(u)[0]

def topic_hits(text):
    low = text.casefold()
    hits = []
    for key, words in TOPICS.items():
        matched = [w for w in words if w.casefold() in low]
        if matched:
            hits.append({"topico": key, "termos": matched[:8]})
    return hits

def extract_pdf_text(content):
    try:
        reader = PdfReader(io.BytesIO(content))
        return "\n".join((p.extract_text() or "") for p in reader.pages[:40])[:120000]
    except Exception:
        return ""

async def fetch_http(client, url):
    try:
        r = await client.get(url, follow_redirects=True, timeout=TIMEOUT)
        return {"url": str(r.url), "status": r.status_code, "content_type": r.headers.get("content-type",""),
                "content": r.content, "error": None}
    except httpx.TimeoutException:
        return {"url":url,"status":None,"content_type":"","content":b"","error":"Tempo limite excedido"}
    except httpx.HTTPStatusError as e:
        return {"url":url,"status":e.response.status_code,"content_type":"","content":b"","error":str(e)}
    except Exception as e:
        return {"url":url,"status":None,"content_type":"","content":b"","error":f"{type(e).__name__}: {e}"}

async def crawl_http(start):
    pages, diagnostics, queue, seen = [], [], deque([(start,0)]), set()
    headers={"User-Agent":USER_AGENT,"Accept":"text/html,application/pdf,application/xhtml+xml,*/*"}
    async with httpx.AsyncClient(headers=headers, verify=True) as client:
        while queue and len(pages)<MAX_PAGES:
            url,depth=queue.popleft()
            url=norm_url(url)
            if url in seen: continue
            seen.add(url)
            result=await fetch_http(client,url)
            if result["error"]:
                diagnostics.append({"url":url,"status":result["status"],"detail":result["error"],"strategy":"HTTP direto"})
                continue
            status=result["status"]; ctype=result["content_type"].lower()
            if status and status>=400:
                diagnostics.append({"url":url,"status":status,"detail":f"Resposta HTTP {status}","strategy":"HTTP direto"})
                continue
            if "pdf" in ctype or url.lower().endswith(".pdf"):
                text=extract_pdf_text(result["content"])
                if text:
                    pages.append({"url":result["url"],"text":text,"kind":"PDF","status":status})
                else:
                    diagnostics.append({"url":url,"status":status,"detail":"PDF localizado, mas não foi possível extrair texto (pode ser digitalizado/imagem).","strategy":"Leitura de PDF"})
                continue
            if "html" not in ctype and "xhtml" not in ctype and not result["content"][:100].lstrip().startswith(b"<"):
                continue
            soup=BeautifulSoup(result["content"],"html.parser")
            for tag in soup(["script","style","noscript","svg"]): tag.decompose()
            text=soup.get_text(" ",strip=True)
            if text: pages.append({"url":result["url"],"text":text[:100000],"kind":"HTML","status":status})
            if depth<MAX_DEPTH:
                for a in soup.find_all("a",href=True):
                    href=urljoin(result["url"],a["href"])
                    if same_host(start,href) and urlparse(href).scheme in ("http","https"):
                        label=(a.get_text(" ",strip=True)+" "+href).casefold()
                        # Prioritize likely transparency/publication pages, but keep broad same-host crawl.
                        if any(k in label for k in ["transpar","legis","normat","receita","despesa","empen","diaria","licita","contrat","conv","obra","servid","folha","sess","projeto","publica","document","arquivo","pdf"]):
                            queue.append((norm_url(href),depth+1))
                        elif depth==0 and len(queue)<MAX_PAGES//2:
                            queue.append((norm_url(href),depth+1))
    return pages, diagnostics

async def crawl_playwright(start):
    # Optional fallback for JavaScript-rendered pages. It does not bypass login, CAPTCHA or access controls.
    try:
        from playwright.async_api import async_playwright
    except Exception:
        return [], [{"url":start,"status":None,"detail":"Playwright não está instalado no ambiente.","strategy":"Navegador automatizado"}]
    pages=[]; diag=[]
    try:
        async with async_playwright() as p:
            browser=await p.chromium.launch(headless=True)
            page=await browser.new_page(user_agent=USER_AGENT)
            await page.goto(start,wait_until="domcontentloaded",timeout=int(TIMEOUT*1000))
            await page.wait_for_timeout(1800)
            text=await page.locator("body").inner_text(timeout=8000)
            pages.append({"url":page.url,"text":text[:100000],"kind":"HTML renderizado","status":200})
            links=await page.locator("a[href]").evaluate_all("(els)=>els.map(a=>({href:a.href,text:a.innerText||''})).slice(0,45)")
            for item in links:
                u=item.get("href","")
                if u and same_host(start,u) and any(k in (u+" "+item.get("text","")).casefold() for k in ["transpar","legis","normat","receita","despesa","empen","diaria","licita","contrat","conv","obra","servid","folha","sess","projeto","publica"]):
                    try:
                        await page.goto(u,wait_until="domcontentloaded",timeout=int(TIMEOUT*1000))
                        await page.wait_for_timeout(700)
                        t=await page.locator("body").inner_text(timeout=5000)
                        pages.append({"url":page.url,"text":t[:100000],"kind":"HTML renderizado","status":200})
                    except Exception as e:
                        diag.append({"url":u,"status":None,"detail":str(e)[:250],"strategy":"Navegador automatizado"})
            await browser.close()
    except Exception as e:
        diag.append({"url":start,"status":None,"detail":f"{type(e).__name__}: {e}","strategy":"Navegador automatizado"})
    return pages,diag

def make_candidates(pages):
    results={k:[] for k in TOPICS}
    for page in pages:
        text=page["text"]
        hits=topic_hits(text)
        for hit in hits:
            key=hit["topico"]
            terms=hit["termos"]
            # Capture nearby sentence-like fragments, retaining the source text verbatim.
            low=text.casefold()
            spans=[]
            for term in terms:
                pos=0; t=term.casefold()
                while len(spans)<8:
                    idx=low.find(t,pos)
                    if idx<0: break
                    start=max(0,text.rfind(".",0,idx)+1)
                    end=text.find(".",idx)
                    if end<0: end=min(len(text),idx+360)
                    else: end=min(end+1,idx+500)
                    frag=" ".join(text[start:end].split())
                    if frag and frag not in spans: spans.append(frag)
                    pos=idx+len(t)
            if spans:
                results[key].append({"url":page["url"],"tipo_fonte":page["kind"],"trechos":spans[:5],
                    "datas_encontradas":list(dict.fromkeys(DATE_RE.findall(" ".join(spans))))[:12],
                    "numeracoes_encontradas":list(dict.fromkeys(NUM_RE.findall(" ".join(spans))))[:12]})
    return results

@app.get("/")
def root():
    return {"service":APP_NAME,"version":"0.1.0","status":"online","docs":"/docs"}

@app.get("/health")
def health():
    return {"status":"ok","service":APP_NAME}

@app.post("/audit")
async def audit(req: AuditRequest):
    try:
        start=safe_public_url(str(req.portal))
    except ValueError as e:
        raise HTTPException(status_code=400,detail=str(e))
    # Strategy 1: discover API/document endpoints through HTML link metadata and common API paths.
    # Strategy 2: direct HTTP crawl.
    pages, http_diag=await crawl_http(start)
    diagnostics=[
        {"titulo":"Estratégia 1 — APIs/dados estruturados","status":"Verificação exploratória","detalhe":"A varredura HTTP identifica links e conteúdo estruturado acessível; APIs privadas ou específicas podem exigir integração própria."},
        {"titulo":"Estratégia 2 — Consulta HTTP direta","status":"Concluída" if pages else "Falha/sem conteúdo legível","detalhe":f"{len(pages)} páginas/documentos lidos por HTTP direto."}
    ]
    diagnostics.extend([{"titulo":x["strategy"]+" — "+x["url"],"status":f"HTTP {x['status']}" if x["status"] else "Falha de acesso","detalhe":x["detail"]} for x in http_diag[:25]])
    # Strategy 3: browser rendering if HTTP crawl yielded little content or JS hints.
    if len(pages)<4:
        rendered, render_diag=await crawl_playwright(start)
        pages.extend(rendered)
        diagnostics.append({"titulo":"Estratégia 3 — Navegador automatizado","status":"Concluída" if rendered else "Não foi possível concluir","detalhe":f"{len(rendered)} páginas renderizadas por navegador."})
        diagnostics.extend([{"titulo":"Navegador automatizado — "+x["url"],"status":"Falha","detalhe":x["detail"]} for x in render_diag[:15]])
    else:
        diagnostics.append({"titulo":"Estratégia 3 — Navegador automatizado","status":"Não acionada","detalhe":"A consulta HTTP já encontrou conteúdo suficiente para a varredura inicial. Será acionada em uma próxima tentativa se a coleta for insuficiente."})
    # Strategy 4 is PDF text extraction, already attempted for PDFs discovered in crawl.
    pdfs=[p for p in pages if p["kind"]=="PDF"]
    diagnostics.append({"titulo":"Estratégia 4 — Leitura de PDFs/documentos","status":"Concluída" if pdfs else "Nenhum PDF legível localizado","detalhe":f"{len(pdfs)} PDF(s) com texto extraído. PDFs digitalizados podem exigir OCR."})
    candidates=make_candidates(pages)
    summary={k:len(v) for k,v in candidates.items()}
    # Never assert "not found" as absence: the scan is only a bounded discovery pass.
    return {
        "orgao":req.orgao,"municipio":req.municipio,"portal":start,"data_referencia":req.data_referencia,
        "paginas_lidas":len(pages),"resumo_candidatos":summary,"candidatos":candidates,
        "diagnosticos":diagnostics,
        "aviso":"A varredura automática identifica candidatos e evidências textuais, mas não garante cobertura integral de todo portal. Confirme cada dado na fonte antes de publicar o relatório. Não foi contornado CAPTCHA, login ou bloqueio de segurança."
    }
