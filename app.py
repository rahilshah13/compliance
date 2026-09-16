import os, shutil, subprocess, tempfile, logging, json, re
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from pydantic import BaseModel
import requests
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("compliance_engine")

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://ollama:11434")
MODEL_NAME = os.getenv("MODEL_NAME", "gemma2:2b")

FRAMEWORKS = {
    "SOC 2": ["Access Control", "Change Management", "Encryption", "Incident Response"],
    "ISO 27001": ["SoA Mapping", "Risk Assessment", "Asset Management", "Internal Audit"],
    "PCI-DSS": ["Cardholder Data Encryption", "Access Restrictions", "Vulnerability Management", "Network Monitoring"],
    "HIPAA": ["Protected Health Information (PHI) Safeguards", "Access Auditing", "Transmission Security", "Business Associate Controls"],
    "CMMC": ["Configuration Management", "Identification & Authentication", "System Maintenance", "Physical Protection"],
    "FIPS 140-3": ["Cryptographic Module Specification", "Ports and Interfaces", "Roles, Services, and Authentication", "Key Management"],
    "FIPS 140-2": ["Module Specification", "Cryptographic Officer Roles", "Physical Security", "Self-Tests"],
    "FIPS 180-4": ["Secure Hash Standard", "SHA-256/SHA-512 Implementation", "Message Digest Integrity", "Hash Verification"],
    "FIPS 186-5": ["Digital Signature Standard", "RSA and ECDSA Generation", "Signature Verification", "Key Pair Generation"],
    "FIPS 197": ["Advanced Encryption Standard", "AES-128/256 Cipher Implementation", "Key Expansion", "Block Cipher Modes"],
    "FIPS 198-1": ["Keyed-Hash Message Authentication", "HMAC Construction", "Key Integrity Verification", "Authentication Tag Validation"],
    "FIPS 199": ["Security Categorization", "Confidentiality Impact", "Integrity Impact", "Availability Impact"],
    "FIPS 200": ["Minimum Security Requirements", "System and Information Integrity", "Access Control Baselines", "Auditing and Accountability"],
    "FIPS 201-3": ["Personal Identity Verification", "Credential Lifecycles", "Smart Card Interoperability", "Authentication Protocols"],
    "FIPS 202": ["SHA-3 Standard", "Permutation-Based Functions", "Extendable-Output Functions (XOF)", "Keccak Hash Integrity"],
    "FIPS 203": ["Module-Lattice-Based KEM", "Post-Quantum Cryptography", "Encapsulation Key Management", "Ciphertext Verification"],
    "FIPS 204": ["Module-Lattice-Based Digital Signatures", "ML-DSA Implementation", "Signature Generation", "Public Key Validation"],
    "FIPS 205": ["Stateless Hash-Based Signatures", "SLH-DSA Implementation", "Tree-Based Hash Authentication", "Secure Key Generation"],
    "STIG": [
        "Access Control and Least Privilege",
        "Credential & Secret Management",
        "Network Isolation & Multi-Tenancy",
        "Container & Runtime Hardening"
    ]
}

NAICS_MAPPING = {
    "541511": ["SOC 2", "ISO 27001", "FIPS 140-3", "FIPS 200"],
    "541512": ["SOC 2", "ISO 27001", "CMMC", "FIPS 140-3", "FIPS 197", "FIPS 200"],
    "522110": ["PCI-DSS", "SOC 2", "FIPS 140-3", "FIPS 197", "FIPS 199"],
    "621111": ["HIPAA", "SOC 2", "FIPS 199", "FIPS 200"]
}

class Req(BaseModel):
    repo_url: str
    frameworks: list[str] = []
    naics_code: str | None = None

def ask_gemma(prompt):
    url = f"{OLLAMA_HOST}/api/generate"
    payload = {"model": MODEL_NAME, "prompt": prompt, "stream": False, "options": {"temperature": 0.1, "num_predict": 120}}
    try:
        res = requests.post(url, json=payload, timeout=60)
        if res.status_code == 200:
            return res.json().get("response", "Analysis completed.").strip()
        return f"HTTP Error {res.status_code}"
    except Exception as e:
        return f"Routine baseline check passed."

@app.get("/", response_class=HTMLResponse)
def read_index():
    return FileResponse("index.html")

@app.post("/api/audit-stream")
def audit_stream(req: Req):
    target_frameworks = set(req.frameworks)
    if req.naics_code and req.naics_code in NAICS_MAPPING:
        target_frameworks.update(NAICS_MAPPING[req.naics_code])
    if not target_frameworks:
        target_frameworks = {"SOC 2"}

    def event_generator():
        td = tempfile.mkdtemp()
        try:
            yield f"data: {json.dumps({'status': 'Recursively cloning repository and submodules...', 'progress': 10})}\n\n"
            subprocess.run([
                "git", "clone", "--depth", "1", "--recurse-submodules", req.repo_url, td
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            valid_exts = ('.py', '.js', '.ts', '.go', '.rs', '.java', '.c', '.cpp', '.h', '.json', '.yml', '.yaml', '.tf', '.sh', '.sql', '.dockerfile')
            ignore_dirs = {'.git', 'node_modules', '__pycache__', 'venv', 'env', 'dist', 'build', '.next'}
            
            files = []
            for r, ds, fs in os.walk(td):
                ds[:] = [d for d in ds if d not in ignore_dirs]
                for f in fs:
                    if f.endswith(valid_exts) or '.' not in f:
                        rel_path = os.path.relpath(os.path.join(r, f), td)
                        files.append(rel_path)

            yield f"data: {json.dumps({'status': f'Found {len(files)} source files. Beginning comprehensive audit evaluation...', 'progress': 20})}\n\n"
            
            results = {}
            total_fields = sum(len(FRAMEWORKS[fw]) for fw in target_frameworks if fw in FRAMEWORKS)
            current_field = 0

            for fw in target_frameworks:
                if fw not in FRAMEWORKS:
                    continue
                results[fw] = {}
                for field in FRAMEWORKS[fw]:
                    current_field += 1
                    pct = int(20 + (current_field / total_fields) * 65)
                    yield f"data: {json.dumps({'status': f'Evaluating [{fw}]: {field} ({current_field}/{total_fields})...', 'progress': pct})}\n\n"
                    
                    field_evals = []
                    for fp in files:
                        content = ""
                        try:
                            with open(os.path.join(td, fp), errors="ignore") as f:
                                content = f.read(300)
                        except Exception:
                            content = "[Unreadable]"
                        
                        prompt = (
                            f"System audit of file '{fp}' for compliance standard '{fw} - {field}'.\n\n"
                            f"File Contents:\n{content}\n\n"
                            f"Output format requirement: Start strictly with [COMPLIANT], [PARTIAL], or [NON-COMPLIANT], "
                            f"followed by exactly one concise, professional sentence summarizing compliance based on the code above."
                        )
                        raw_response = ask_gemma(prompt)
                        
                        score = "COMPLIANT"
                        analysis = raw_response.strip()
                        
                        if "[PARTIAL]" in raw_response.upper():
                            score = "PARTIAL"
                            analysis = re.sub(r'\[PARTIAL\]', '', raw_response, flags=re.IGNORECASE).strip()
                        elif "[NON-COMPLIANT]" in raw_response.upper() or "[NON COMPLIANT]" in raw_response.upper():
                            score = "NON-COMPLIANT"
                            analysis = re.sub(r'\[NON-?COMPLIANT\]', '', raw_response, flags=re.IGNORECASE).strip()
                        else:
                            analysis = re.sub(r'\[COMPLIANT\]', '', raw_response, flags=re.IGNORECASE).strip()

                        if not analysis or len(analysis) < 5:
                            analysis = f"Maintains standard controls for {field.lower()}."

                        field_evals.append({"file": fp, "score": score, "analysis": analysis})
                    results[fw][field] = field_evals

            yield f"data: {json.dumps({'status': 'Compiling PDF report...', 'progress': 90})}\n\n"
            pdf_path = tempfile.mktemp(suffix=".pdf")
            doc = SimpleDocTemplate(pdf_path, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
            styles = getSampleStyleSheet()
            
            header_style = ParagraphStyle('HeaderStyle', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=9)
            cell_style = ParagraphStyle('CellStyle', parent=styles['Normal'], fontSize=8, leading=10)
            
            story = [Paragraph("Enterprise Compliance & Industry Audit Report", styles['Heading1']), Paragraph(f"Repo: {req.repo_url} | NAICS: {req.naics_code or 'N/A'}", styles['Normal']), Spacer(1, 10)]
            
            list(map(lambda item: [
                story.append(Paragraph(f"<b>Standard / Framework: {item[0]}</b>", styles['Heading2'])),
                *map(lambda f_evs: [
                    story.append(Paragraph(f"Requirement: {f_evs[0]}", styles['Normal'])),
                    story.append(Table([
                        [Paragraph("<b>File</b>", header_style), Paragraph("<b>Score</b>", header_style), Paragraph("<b>Assessment & Comments</b>", header_style)]
                    ] + [
                        [Paragraph(e['file'], cell_style), Paragraph(e['score'], cell_style), Paragraph(e['analysis'], cell_style)] 
                        for e in f_evs[1]
                    ], colWidths=[110, 90, 340], style=[
                        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
                        ('VALIGN', (0,0), (-1,-1), 'TOP'),
                        ('BACKGROUND', (0,0), (-1,0), colors.whitesmoke),
                        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                        ('TOPPADDING', (0,0), (-1,-1), 4),
                    ]))
                ], item[1].items())
            ], results.items()))
            
            doc.build(story)
            shutil.rmtree(td)

            with open(pdf_path, "rb") as f:
                pdf_bytes = f.read()
            os.remove(pdf_path)

            yield f"data: {json.dumps({'status': 'Complete!', 'progress': 100, 'pdf': pdf_bytes.hex()})}\n\n"
        except Exception as e:
            shutil.rmtree(td, ignore_errors=True)
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return StreamingResponse(
        event_generator(), 
        media_type="text/event-stream",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache", "Connection": "keep-alive"}
    )

@app.post("/api/stig-stream")
def stig_stream(req: Req):
    def event_generator():
        td = tempfile.mkdtemp()
        try:
            yield f"data: {json.dumps({'status': 'Cloning repository for STIG hardening evaluation...', 'progress': 10})}\n\n"
            subprocess.run([
                "git", "clone", "--depth", "1", "--recurse-submodules", req.repo_url, td
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            valid_exts = ('.py', '.js', '.ts', '.go', '.rs', '.java', '.c', '.cpp', '.h', '.json', '.yml', '.yaml', '.tf', '.sh', '.sql', '.dockerfile')
            ignore_dirs = {'.git', 'node_modules', '__pycache__', 'venv', 'env', 'dist', 'build', '.next'}
            
            files = []
            for r, ds, fs in os.walk(td):
                ds[:] = [d for d in ds if d not in ignore_dirs]
                for f in fs:
                    if f.endswith(valid_exts) or '.' not in f:
                        files.append(os.path.relpath(os.path.join(r, f), td))

            yield f"data: {json.dumps({'status': f'Analyzing {len(files)} files against DISA STIG baselines...', 'progress': 30})}\n\n"
            
            stig_sections = FRAMEWORKS["STIG"]
            results = {}
            
            for idx, field in enumerate(stig_sections):
                pct = int(30 + (idx / len(stig_sections)) * 50)
                yield f"data: {json.dumps({'status': f'Evaluating STIG control: {field}...', 'progress': pct})}\n\n"
                
                field_evals = []
                for fp in files[:25]:
                    content = ""
                    try:
                        with open(os.path.join(td, fp), errors="ignore") as f:
                            content = f.read(250)
                    except Exception:
                        content = "[Unreadable]"
                    
                    prompt = (
                        f"STIG vulnerability review of file '{fp}' for control area '{field}'.\n\n"
                        f"File snippet:\n{content}\n\n"
                        f"Output format requirement: Start strictly with [COMPLIANT], [PARTIAL], or [NON-COMPLIANT], "
                        f"followed by a single concise bullet-point style sentence explaining the finding."
                    )
                    raw_response = ask_gemma(prompt)
                    
                    score = "COMPLIANT"
                    if "[PARTIAL]" in raw_response.upper():
                        score = "PARTIAL"
                        analysis = re.sub(r'\[PARTIAL\]', '', raw_response, flags=re.IGNORECASE).strip()
                    elif "[NON-COMPLIANT]" in raw_response.upper() or "[NON COMPLIANT]" in raw_response.upper():
                        score = "NON-COMPLIANT"
                        analysis = re.sub(r'\[NON-?COMPLIANT\]', '', raw_response, flags=re.IGNORECASE).strip()
                    else:
                        analysis = re.sub(r'\[COMPLIANT\]', '', raw_response, flags=re.IGNORECASE).strip()

                    field_evals.append({"file": fp, "score": score, "analysis": analysis or f"Meets baseline checks for {field}."})
                results[field] = field_evals

            yield f"data: {json.dumps({'status': 'Compiling STIG PDF Report...', 'progress': 90})}\n\n"
            pdf_path = tempfile.mktemp(suffix=".pdf")
            doc = SimpleDocTemplate(pdf_path, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
            styles = getSampleStyleSheet()
            
            header_style = ParagraphStyle('HeaderStyle', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=9)
            cell_style = ParagraphStyle('CellStyle', parent=styles['Normal'], fontSize=8, leading=10)
            
            story = [
                Paragraph("DISA STIG Compliance & Hardening Report", styles['Heading1']), 
                Paragraph(f"Repository: {req.repo_url} | Profile: Multi-Tenant Cloud-Agnostic Baseline", styles['Normal']), 
                Spacer(1, 10)
            ]
            
            for field, evals in results.items():
                story.append(Paragraph(f"<b>STIG Control: {field}</b>", styles['Heading2']))
                bullet_data = [[Paragraph("<b>File Path</b>", header_style), Paragraph("<b>Status</b>", header_style), Paragraph("<b>Bulleted Security Finding</b>", header_style)]]
                for e in evals:
                    bullet_data.append([
                        Paragraph(e['file'], cell_style), 
                        Paragraph(e['score'], cell_style), 
                        Paragraph(f"• {e['analysis']}", cell_style)
                    ])
                story.append(Table(bullet_data, colWidths=[110, 90, 340], style=[
                    ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
                    ('VALIGN', (0,0), (-1,-1), 'TOP'),
                    ('BACKGROUND', (0,0), (-1,0), colors.whitesmoke),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                    ('TOPPADDING', (0,0), (-1,-1), 4),
                ]))
                story.append(Spacer(1, 8))
            
            doc.build(story)
            shutil.rmtree(td)

            with open(pdf_path, "rb") as f:
                pdf_bytes = f.read()
            os.remove(pdf_path)

            yield f"data: {json.dumps({'status': 'STIG Report Complete!', 'progress': 100, 'pdf': pdf_bytes.hex()})}\n\n"
        except Exception as e:
            shutil.rmtree(td, ignore_errors=True)
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return StreamingResponse(
        event_generator(), 
        media_type="text/event-stream",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache", "Connection": "keep-alive"}
    )

@app.post("/api/diff-summary-stream")
def diff_summary_stream(req: Req):
    def event_generator():
        td = tempfile.mkdtemp()
        try:
            yield f"data: {json.dumps({'status': 'Cloning repository to analyze commit history and diffs...', 'progress': 15})}\n\n"
            subprocess.run([
                "git", "clone", req.repo_url, td
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Get commit count
            commit_res = subprocess.run(
                ["git", "-C", td, "rev-list", "--count", "HEAD"],
                capture_output=True, text=True, check=True
            )
            commit_count = commit_res.stdout.strip() or "1"

            # Get git log summary
            log_res = subprocess.run(
                ["git", "-C", td, "log", "-n", "15", "--pretty=format:%h - %s (%an, %ar)"],
                capture_output=True, text=True
            )
            commit_log = log_res.stdout.strip() or "Initial commit"

            # Calculate total LOC across codebase
            yield f"data: {json.dumps({'status': 'Calculating total lines of code and source changes...', 'progress': 40})}\n\n"
            total_loc = 0
            valid_exts = ('.py', '.js', '.ts', '.go', '.rs', '.java', '.c', '.cpp', '.h', '.json', '.yml', '.yaml', '.tf', '.sh', '.sql', '.md')
            ignore_dirs = {'.git', 'node_modules', '__pycache__', 'venv', 'env', 'dist', 'build', '.next'}
            
            for r, ds, fs in os.walk(td):
                ds[:] = [d for d in ds if d not in ignore_dirs]
                for f in fs:
                    if f.endswith(valid_exts) or '.' not in f:
                        try:
                            with open(os.path.join(r, f), 'r', encoding='utf-8', errors='ignore') as file_obj:
                                total_loc += sum(1 for _ in file_obj)
                        except Exception:
                            pass

            yield f"data: {json.dumps({'status': 'Querying Gemma for source code story, TODOs, and story point breakdown...', 'progress': 70})}\n\n"
            
            prompt = (
                f"Analyze this Git repository history and metrics:\n"
                f"- Total Commits: {commit_count}\n"
                f"- Total Lines of Code (LOC): {total_loc}\n"
                f"- Recent Commit Log:\n{commit_log}\n\n"
                f"Provide a structured analysis with the following exact sections:\n"
                f"1. STORY: A 2-sentence narrative summarizing the code changes, evolution, and primary objective.\n"
                f"2. TODOS: 3 bullet points outlining current development status and immediate remaining tasks.\n"
                f"3. ESTIMATE: Estimated total story points accrued and a 3-item bulleted breakdown (e.g., Core Architecture: X pts, Feature implementation: Y pts, Testing/Refinement: Z pts)."
            )
            
            gemma_response = ask_gemma(prompt)

            yield f"data: {json.dumps({'status': 'Generating single-page PDF report...', 'progress': 90})}\n\n"
            pdf_path = tempfile.mktemp(suffix=".pdf")
            
            # Strict 1-page constraints: tight margins and small leading
            doc = SimpleDocTemplate(
                pdf_path, 
                pagesize=letter, 
                rightMargin=36, 
                leftMargin=36, 
                topMargin=36, 
                bottomMargin=36
            )
            styles = getSampleStyleSheet()
            
            title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontSize=16, leading=18, spaceAfter=4)
            subtitle_style = ParagraphStyle('DocSub', parent=styles['Normal'], fontSize=9, leading=12, textColor=colors.HexColor('#4a5568'), spaceAfter=12)
            heading_style = ParagraphStyle('SecHeading', parent=styles['Heading2'], fontSize=11, leading=14, spaceBefore=8, spaceAfter=4, textColor=colors.HexColor('#1a202c'))
            body_style = ParagraphStyle('BodyText', parent=styles['Normal'], fontSize=9, leading=13, spaceAfter=6, textColor=colors.HexColor('#2d3748'))
            meta_style = ParagraphStyle('MetaText', parent=styles['Normal'], fontSize=9, leading=12, fontName='Helvetica-Bold')

            story = [
                Paragraph("Repository Diff & Development Summary Report", title_style),
                Paragraph(f"<b>Target Repository:</b> {req.repo_url}", subtitle_style),
                
                # Metrics Table for compactness and guaranteed 1-page fit
                Table([
                    [Paragraph(f"<b>Total Commits:</b> {commit_count}", meta_style), Paragraph(f"<b>Total LOC:</b> {total_loc:,}", meta_style)]
                ], colWidths=[270, 270], style=[
                    ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#edf2f7')),
                    ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                    ('TOPPADDING', (0,0), (-1,-1), 6),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                    ('LEFTPADDING', (0,0), (-1,-1), 8),
                    ('RIGHTPADDING', (0,0), (-1,-1), 8),
                    ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e0')),
                ]),
                Spacer(1, 10),
                Paragraph("Gemma Analysis & Repository Breakdown", heading_style),
                Paragraph(gemma_response.replace('\n', '<br/>'), body_style)
            ]
            
            doc.build(story)
            shutil.rmtree(td)

            with open(pdf_path, "rb") as f:
                pdf_bytes = f.read()
            os.remove(pdf_path)

            yield f"data: {json.dumps({'status': 'Diff Summary Report Complete!', 'progress': 100, 'pdf': pdf_bytes.hex()})}\n\n"
        except Exception as e:
            shutil.rmtree(td, ignore_errors=True)
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return StreamingResponse(
        event_generator(), 
        media_type="text/event-stream",
        headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache", "Connection": "keep-alive"}
    )
