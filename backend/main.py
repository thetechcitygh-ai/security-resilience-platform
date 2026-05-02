from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse
from dotenv import load_dotenv
import json
import os
import subprocess
import uuid
import requests


load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "scanner_outputs"
OUTPUT_DIR.mkdir(exist_ok=True)

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")


app = FastAPI(
    title="Security Resilience Platform API",
    version="0.3.0",
    description="Backend API for authorised cyber security resilience assessments."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:5174",
        "https://security-resilience-platform.vercel.app"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    asset_id: str
    target_url: str
    testing_level: str
    frameworks: List[str]
    authorised: bool
    authorisation_ref: str


class ScanResponse(BaseModel):
    job_id: str
    status: str
    message: str
    created_at: str
    target_url: Optional[str] = None
    html_report: Optional[str] = None
    json_report: Optional[str] = None
    zap_exit_code: Optional[int] = None
    saved_findings: int = 0
    highest_risk: Optional[str] = None


def supabase_headers() -> Dict[str, str]:
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise RuntimeError("Supabase backend environment variables are missing.")

    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }


def supabase_insert(table: str, payload: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not payload:
        return []

    response = requests.post(
        f"{SUPABASE_URL}/rest/v1/{table}",
        headers=supabase_headers(),
        data=json.dumps(payload),
        timeout=60
    )

    if response.status_code not in (200, 201):
        raise RuntimeError(f"Supabase insert failed for {table}: {response.text}")

    return response.json()


def supabase_get_asset(asset_id: str) -> Optional[Dict[str, Any]]:
    response = requests.get(
        f"{SUPABASE_URL}/rest/v1/assets",
        headers=supabase_headers(),
        params={
            "id": f"eq.{asset_id}",
            "select": "*"
        },
        timeout=60
    )

    if response.status_code != 200:
        raise RuntimeError(f"Supabase asset lookup failed: {response.text}")

    data = response.json()
    return data[0] if data else None


def supabase_update_asset(asset_id: str, payload: Dict[str, Any]) -> None:
    response = requests.patch(
        f"{SUPABASE_URL}/rest/v1/assets",
        headers=supabase_headers(),
        params={"id": f"eq.{asset_id}"},
        data=json.dumps(payload),
        timeout=60
    )

    if response.status_code not in (200, 204):
        raise RuntimeError(f"Supabase asset update failed: {response.text}")


def normalise_target_url(target_url: str) -> str:
    target = target_url.strip()

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urlparse(target)

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http and https targets are allowed.")

    if not parsed.netloc:
        raise ValueError("Target URL is invalid.")

    return target


def is_private_or_local_target(target_url: str) -> bool:
    parsed = urlparse(target_url)
    hostname = (parsed.hostname or "").lower()

    private_indicators = [
        "localhost",
        "127.",
        "0.0.0.0",
        "10.",
        "192.168.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",
        ".local"
    ]

    return any(hostname.startswith(item) or hostname.endswith(item) for item in private_indicators)


def run_zap_baseline(job_id: str, target_url: str) -> dict:
    html_report = f"{job_id}-zap-report.html"
    json_report = f"{job_id}-zap-report.json"

    use_docker = os.getenv("USE_DOCKER_FOR_ZAP", "false").lower() == "true"

    if use_docker:
        command = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{OUTPUT_DIR}:/zap/wrk/:rw",
            "zaproxy/zap-stable",
            "zap-baseline.py",
            "-t",
            target_url,
            "-r",
            html_report,
            "-J",
            json_report,
            "-m",
            "1"
        ]
    else:
        command = [
            "zap-baseline.py",
            "-t",
            target_url,
            "-r",
            html_report,
            "-J",
            json_report,
            "-m",
            "1"
        ]

    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=900
    )

    log_path = OUTPUT_DIR / f"{job_id}-zap-console.log"
    log_path.write_text(
        "STDOUT:\n"
        + completed.stdout
        + "\n\nSTDERR:\n"
        + completed.stderr,
        encoding="utf-8"
    )

    return {
        "exit_code": completed.returncode,
        "html_report": str(OUTPUT_DIR / html_report),
        "json_report": str(OUTPUT_DIR / json_report),
        "console_log": str(log_path)
    }

def zap_risk_to_platform_severity(alert: Dict[str, Any]) -> str:
    risk = str(alert.get("riskdesc") or alert.get("risk") or "").lower()
    risk_code = str(alert.get("riskcode") or "")

    if "high" in risk or risk_code == "3":
        return "High"

    if "medium" in risk or risk_code == "2":
        return "Medium"

    if "low" in risk or risk_code == "1":
        return "Low"

    return "Informational"


def severity_to_cvss(severity: str) -> float:
    mapping = {
        "Critical": 9.0,
        "High": 7.5,
        "Medium": 5.3,
        "Low": 3.1,
        "Informational": 0.0
    }
    return mapping.get(severity, 0.0)


def highest_risk_from_findings(findings: List[Dict[str, Any]]) -> str:
    severities = {finding.get("severity") for finding in findings}

    if "Critical" in severities:
        return "Critical"

    if "High" in severities:
        return "High"

    if "Medium" in severities:
        return "Medium"

    if "Low" in severities:
        return "Low"

    return "Clean"


def extract_first_uri(alert: Dict[str, Any], fallback_target: str) -> str:
    instances = alert.get("instances") or []

    if isinstance(instances, list) and instances:
        first = instances[0] or {}
        return first.get("uri") or first.get("url") or fallback_target

    return fallback_target


def clean_text(value: Any) -> str:
    if value is None:
        return ""

    text = str(value)
    return (
        text.replace("<p>", "")
        .replace("</p>", "")
        .replace("<br>", "\n")
        .replace("<br/>", "\n")
        .replace("<br />", "\n")
        .strip()
    )


def parse_zap_json_to_findings(
    json_report_path: str,
    asset_id: str,
    target_url: str,
    testing_level: str,
    owner: str
) -> List[Dict[str, Any]]:
    report_path = Path(json_report_path)

    if not report_path.exists():
        return []

    with report_path.open("r", encoding="utf-8") as file:
        zap_data = json.load(file)

    findings = []
    sites = zap_data.get("site") or []

    for site in sites:
        alerts = site.get("alerts") or []

        for alert in alerts:
            severity = zap_risk_to_platform_severity(alert)

            if severity == "Informational":
                status = "Observed"
            else:
                status = "Open"

            plugin_id = alert.get("pluginid") or alert.get("pluginId") or "N/A"
            title = alert.get("name") or alert.get("alert") or f"ZAP Alert {plugin_id}"
            affected_url = extract_first_uri(alert, target_url)
            description = clean_text(alert.get("desc"))
            solution = clean_text(alert.get("solution"))
            evidence = clean_text(alert.get("evidence"))
            reference = clean_text(alert.get("reference"))

            evidence_summary = "\n\n".join(
                item
                for item in [
                    f"Affected URL: {affected_url}",
                    f"ZAP Plugin ID: {plugin_id}",
                    f"Evidence: {evidence}" if evidence else "",
                    f"Reference: {reference}" if reference else "",
                    f"Description: {description}" if description else ""
                ]
                if item
            )

            remediation = solution or "Review the ZAP alert, validate the exposure and apply the recommended security control."

            findings.append(
                {
                    "asset_id": asset_id,
                    "title": title,
                    "severity": severity,
                    "cvss": severity_to_cvss(severity),
                    "cwe": f"ZAP-{plugin_id}",
                    "framework": "OWASP ZAP Baseline / OWASP Top 10 / NIST SP 800-115",
                    "remediation": remediation,
                    "evidence": evidence_summary,
                    "status": status,
                    "owner": owner,
                    "testing_level": testing_level,
                    "target": affected_url
                }
            )

    return findings


@app.get("/")
def root():
    return {
        "service": "Security Resilience Platform API",
        "status": "online",
        "version": "0.3.0"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/scan-jobs", response_model=ScanResponse)
def create_scan_job(request: ScanRequest):
    created_at = datetime.utcnow().isoformat()
    job_id = f"JOB-{uuid.uuid4().hex[:12].upper()}"

    if not request.authorised:
        return ScanResponse(
            job_id="blocked",
            status="blocked",
            message="Scan blocked. Target is not authorised.",
            created_at=created_at
        )

    if not request.authorisation_ref.strip():
        return ScanResponse(
            job_id="blocked",
            status="blocked",
            message="Scan blocked. Authorisation reference is required.",
            created_at=created_at
        )

    try:
        target_url = normalise_target_url(request.target_url)
    except ValueError as error:
        return ScanResponse(
            job_id="blocked",
            status="blocked",
            message=str(error),
            created_at=created_at
        )

    if is_private_or_local_target(target_url):
        return ScanResponse(
            job_id="blocked",
            status="blocked",
            message="Scan blocked. Private or local targets require a separate internal scanner profile.",
            created_at=created_at,
            target_url=target_url
        )

    if request.testing_level != "penetration":
        return ScanResponse(
            job_id=job_id,
            status="queued",
            message="Backend accepted governance workflow. ZAP baseline currently runs only for Penetration Testing level.",
            created_at=created_at,
            target_url=target_url
        )

    try:
        asset = supabase_get_asset(request.asset_id)
    except RuntimeError as error:
        return ScanResponse(
            job_id=job_id,
            status="failed",
            message=str(error),
            created_at=created_at,
            target_url=target_url
        )

    if not asset:
        return ScanResponse(
            job_id=job_id,
            status="failed",
            message="Asset was not found in Supabase.",
            created_at=created_at,
            target_url=target_url
        )

    try:
        zap_result = run_zap_baseline(job_id=job_id, target_url=target_url)
    except subprocess.TimeoutExpired:
        return ScanResponse(
            job_id=job_id,
            status="timeout",
            message="ZAP baseline scan timed out. Try again or reduce the target scope.",
            created_at=created_at,
            target_url=target_url
        )
    except FileNotFoundError:
        return ScanResponse(
            job_id=job_id,
            status="failed",
            message="Docker command was not found. Confirm Docker Desktop is installed and running.",
            created_at=created_at,
            target_url=target_url
        )

    zap_exit_code = zap_result["exit_code"]
    status = "completed" if zap_exit_code in (0, 1, 2) else "failed"

    saved_findings = 0
    highest_risk = "Clean"

    if status == "completed":
        owner = asset.get("owner") or ""
        parsed_findings = parse_zap_json_to_findings(
            json_report_path=zap_result["json_report"],
            asset_id=request.asset_id,
            target_url=target_url,
            testing_level=request.testing_level,
            owner=owner
        )

        if parsed_findings:
            supabase_insert("findings", parsed_findings)
            saved_findings = len(parsed_findings)
            highest_risk = highest_risk_from_findings(parsed_findings)

        current_scan_count = int(asset.get("scan_count") or 0)

        supabase_update_asset(
            request.asset_id,
            {
                "last_scan": datetime.utcnow().isoformat(),
                "risk": highest_risk,
                "scan_count": current_scan_count + 1
            }
        )

    return ScanResponse(
        job_id=job_id,
        status=status,
        message=f"ZAP baseline scan completed. {saved_findings} finding(s) saved to Supabase.",
        created_at=created_at,
        target_url=target_url,
        html_report=zap_result["html_report"],
        json_report=zap_result["json_report"],
        zap_exit_code=zap_exit_code,
        saved_findings=saved_findings,
        highest_risk=highest_risk
    )