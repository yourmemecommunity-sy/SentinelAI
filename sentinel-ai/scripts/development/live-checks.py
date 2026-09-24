#!/usr/bin/env python3
"""Live checks against the RUNNING docker-compose stack (gateway on 127.0.0.1:4000, dashboard on 127.0.0.1:3000).

Prints human-readable evidence; exits non-zero if any check fails. It creates a throwaway organization and API key, and
never prints the key. Run it with a Python that has Pillow (to draw the test screenshot) where loopback reaches the stack,
e.g. inside WSL with the document scanner's dev virtualenv (scripts/development/wsl-docscanner.sh setup creates it):

    /opt/dsvenv/bin/python scripts/development/live-checks.py

(The document-scanner image itself has no Pillow: it pipes images to the tesseract binary.)

Checks: gateway /ready; /v1/security/scan masks PII and blocks a credential; the dashboard serves its login page;
/v1/files/scan blocks the EICAR test file (real ClamAV in the stack) and OCRs a PNG screenshot containing a fake email,
which comes back masked (real Tesseract in the stack).
"""
from __future__ import annotations

import io
import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any

API = "http://127.0.0.1:4000"
DASH = "http://127.0.0.1:3000"
FAILED: list[str] = []


def call(method: str, url: str, body: bytes | None = None, headers: dict[str, str] | None = None) -> tuple[int, bytes, dict[str, str]]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def jcall(method: str, url: str, obj: Any, headers: dict[str, str]) -> tuple[int, Any]:
    status, raw, _ = call(method, url, json.dumps(obj).encode(), {"content-type": "application/json", **headers})
    return status, json.loads(raw or b"{}")


def is_blocked(status: int, r: dict[str, Any]) -> bool:
    return r.get("decision") in ("BLOCK", "QUARANTINE") or (status == 403 and r.get("error") == "blocked")


def check(name: str, ok: bool, detail: str) -> None:
    print(f"{'PASS' if ok else 'FAIL'} {name}\n     {detail}")
    if not ok:
        FAILED.append(name)


def png_with_text(lines: list[str]) -> bytes:
    from PIL import Image, ImageDraw, ImageFont

    img = Image.new("RGB", (1400, 90 + 70 * len(lines)), "white")
    d = ImageDraw.Draw(img)
    font: Any = ImageFont.load_default()
    for path in ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"):
        try:
            font = ImageFont.truetype(path, 44)
            break
        except OSError:
            continue
    for i, line in enumerate(lines):
        d.text((30, 30 + 70 * i), line, fill="black", font=font)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def main() -> int:
    # 1. readiness
    status, raw, _ = call("GET", f"{API}/ready")
    check("gateway /ready", status == 200, f"HTTP {status} {raw.decode()[:200]}")

    # 2. a throwaway organization + DEVELOPER API key (never printed)
    slug = f"live-{int(time.time())}"
    s, signup = jcall("POST", f"{API}/v1/auth/signup", {"organization_name": slug, "email": f"{slug}@example.com",
                                                          "password": "Live-Check-Passw0rd!"}, {})
    check("signup", s == 201, f"HTTP {s}")
    s, key = jcall("POST", f"{API}/v1/api-keys", {"name": "live-check", "role": "DEVELOPER"},
                   {"authorization": f"Bearer {signup.get('access_token', '')}"})
    check("create API key", s == 201 and str(key.get("key", "")).startswith("snl_"), f"HTTP {s}, key prefix snl_ (value not printed)")
    auth = {"x-sentinel-api-key": key.get("key", "")}

    # 3. /v1/security/scan: PII is masked, a credential is blocked
    s, r = jcall("POST", f"{API}/v1/security/scan", {"text": "Please email jane.doe@example.com about the invoice."}, auth)
    ents = sorted({d["entity"] for d in r.get("detections", [])})
    check("scan masks an email", s == 200 and r.get("decision") == "MASK" and "jane.doe@" not in str(r.get("sanitized_text")),
          f"HTTP {s} decision={r.get('decision')} entities={ents} sanitized_text={r.get('sanitized_text')!r}")
    aws = "AK" + "IA" + "LIVECHECK" + "7EXAMPL"  # assembled at runtime: correctly shaped, not a real credential
    s, r = jcall("POST", f"{API}/v1/security/scan", {"text": f"deploy with access key {aws}"}, auth)
    ents = sorted({d["entity"] for d in r.get("detections", [])})
    check("scan blocks a credential", s == 200 and r.get("decision") == "BLOCK" and r.get("sanitized_text") is None,
          f"HTTP {s} decision={r.get('decision')} entities={ents} sanitized_text={r.get('sanitized_text')!r}")

    # 4. dashboard over HTTP
    status, raw, headers = call("GET", f"{DASH}/login")
    html = raw.decode(errors="replace")
    title = html.split("<title>")[1].split("</title>")[0] if "<title>" in html else "?"
    check("dashboard serves /login over HTTP", status == 200 and "<html" in html.lower(),
          f"HTTP {status}, {len(raw)} bytes, <title>{title}</title>, CSP header present: {'content-security-policy' in {k.lower() for k in headers}}")

    # 5. /v1/files/scan: EICAR is blocked by the real antivirus; a screenshot's email is OCR'd and masked
    eicar = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()  # the public AV test string
    status, raw, _ = call("POST", f"{API}/v1/files/scan", eicar, {"content-type": "application/octet-stream", "x-filename": "readme.txt", **auth})
    r = json.loads(raw or b"{}")
    # Must be a real signature hit: a block for any other reason (e.g. malware_scan_failed while ClamAV restarts) is a correct
    # fail-closed outcome, but it would not prove that the antivirus actually recognised the file.
    check("EICAR upload is blocked (real ClamAV)", is_blocked(status, r) and r.get("reason") == "malware_detected" and r.get("sanitized_text") is None,
          f"HTTP {status} decision={r.get('decision')} reason={r.get('reason')} failed_closed={r.get('failed_closed')} "
          f"findings={[(f.get('type'), f.get('detail')) for f in r.get('findings', [])][:4]}")
    png = png_with_text(["Customer contact:", "jane.doe@example.com"])
    status, raw, _ = call("POST", f"{API}/v1/files/scan", png, {"content-type": "application/octet-stream", "x-filename": "screenshot.png", **auth})
    r = json.loads(raw or b"{}")
    text = str(r.get("sanitized_text"))
    check("screenshot email is OCR'd and masked (real Tesseract)",
          status == 200 and not is_blocked(status, r) and "jane.doe@" not in text and "@example.com" in text,
          f"HTTP {status} decision={r.get('decision')} ocr_used={r.get('file', {}).get('ocr_used')} "
          f"entities={sorted({d['entity'] for d in r.get('detections', [])})} sanitized_text={text!r}")

    print(f"\nLIVE CHECKS: {'ALL PASSED' if not FAILED else 'FAILED: ' + ', '.join(FAILED)}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
