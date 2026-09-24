# Task 5 — Real ClamAV + Tesseract

Run: **2026-09-26 07:51–08:31 UTC**.

| Check | Result |
|---|---|
| Real-dependency tests (`tests/test_real_dependencies.py`) with **ClamAV 1.5.4** (clamd) and **Tesseract 5.5.0** in WSL | **16 passed** (these are the 16 that skip on the Windows host) |
| Whole document-scanner suite with the real daemon + binary present | **133 passed, 0 skipped** |
| EICAR through the running stack (containerised ClamAV) | **Blocked** — `decision=BLOCK reason=malware_detected`, finding `signature Eicar-Test-Signature` |
| Image containing a fake email through the running stack (containerised Tesseract) | **Detected and masked** — `decision=MASK ocr_used=True entities=['EMAIL'] sanitized_text='Customer contact:
j***@example.com
'` |

The EICAR string is the public antivirus test file, assembled at runtime by the script (never stored in the repository).
```
# STEP 5 - Real ClamAV + Tesseract  (2026-09-26T07:51:25Z)
clamd PING -> PONG   ClamAV 1.5.4/28131/Tue Sep 22 06:27:06 2026   tesseract 5.5.0

## Real-dependency tests (tests/test_real_dependencies.py, verbose)
exit 0
============================== 16 passed in 3.11s ==============================

## Whole document-scanner suite with the real daemon and binary present
exit 0
133 passed, 3 warnings in 15.29s

## Through the running stack (containerised ClamAV + Tesseract): see the file-scan checks in step2.log
PASS EICAR upload is blocked (real ClamAV)
     HTTP 200 decision=BLOCK reason=malware_detected failed_closed=False findings=[('malware_detected', 'signature Eicar-Test-Signature')]
--
PASS EICAR is detected by REAL ClamAV and blocked  (malware_detected)
PASS no credentials -> 401
STEPS25_DONE wall 564s vs VM 564s
```

## Real-dependency test output
```
============================= test session starts ==============================
platform linux -- Python 3.14.4, pytest-9.1.1, pluggy-1.6.0
rootdir: /tmp/ds
configfile: pyproject.toml
plugins: anyio-4.15.1
collected 16 items

tests/test_real_dependencies.py ................                         [100%]

============================== 16 passed in 3.11s ==============================
```
