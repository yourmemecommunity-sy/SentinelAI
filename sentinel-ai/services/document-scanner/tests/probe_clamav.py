"""Ad-hoc probe (not collected by pytest: no test_ prefix). Shows what the REAL clamd says about EICAR in various positions.

    /opt/dsvenv/bin/python tests/probe_clamav.py
"""
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.malware.scanners import EICAR, ClamdScanner  # noqa: E402

s = ClamdScanner(os.environ.get("CLAMD_HOST", "127.0.0.1"), int(os.environ.get("CLAMD_PORT", "3310")), 30.0)
from PIL import Image, ImageDraw  # noqa: E402

img = Image.new("RGB", (300, 100), "white")
ImageDraw.Draw(img).text((10, 10), "hello", fill="black")
buf = io.BytesIO()
img.save(buf, format="PNG")
png = buf.getvalue()

print("healthy      :", s.healthy())
print("clean text   :", s.scan(b"ordinary text"))
print("raw EICAR    :", s.scan(EICAR))
print("PNG + EICAR  :", s.scan(png + b"\n" + EICAR))
print("EICAR + PNG  :", s.scan(EICAR + b"\n" + png))
print("text + EICAR :", s.scan(b"invoice notes\n" + EICAR))
