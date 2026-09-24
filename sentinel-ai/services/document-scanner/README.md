# document-scanner

Turns an untrusted uploaded file into **safe text** or a **BLOCK**, before any of it reaches a model.
It never stores the upload (memory only), never logs file names or content, and fails closed: every
parser error, limit hit, or missing capability is a BLOCK with empty text.

```
POST /v1/extract   raw bytes, headers X-Filename (extension only is used), X-Internal-Token
  1. size cap (streamed; 413)
  2. content sniffing by magic bytes against an allow-list; extension/content mismatch -> BLOCK
  3. malware scan BEFORE any parser touches the bytes (clamd INSTREAM; EICAR baseline in dev)
  4. images -> OCR (Tesseract via stdin); everything else -> parser in an isolated child process
  5. text cap (blocks, never truncates)
```

Supported: PDF, DOCX, XLSX, CSV, TXT, JSON, PNG, JPEG, GIF, WEBP.

| Threat | Handling |
|---|---|
| Disguised type | Magic-byte sniffing; mismatch with the claimed extension is blocked |
| Zip bomb / path traversal / duplicate or encrypted members | Hardened ZIP reader: entry cap, ratio cap, shared read budget |
| Macros, OLE, ActiveX, embeddings, external templates/frames | Blocked (OOXML) |
| PDF JavaScript, Launch, embedded files, RichMedia, encryption | Blocked (raw-byte and parsed-object walk, including compressed object streams) |
| Hidden text (white/tiny/vanish), comments, tracked deletions, metadata | Extracted **and flagged**, so hidden prompt injection is scanned |
| XXE / entity expansion | `defusedxml` |
| Parser crash / hang | Child process with a hard timeout, killed on expiry |
| Malware | clamd; unreachable scanner = BLOCK (production refuses to start with anything else) |

## Configuration
See `.env.example` (`DOC_SCANNER_TOKEN`, `MALWARE_SCANNER`, `CLAMD_HOST/PORT`, `TESSERACT_CMD`, limits).
`SENTINEL_ENV=production` refuses to start without a token, without `MALWARE_SCANNER=clamd`, or with isolation off.

## Tests
```
python -m pytest        # 117 tests: benign + hostile synthetic files, limits, isolation, API
python tests/make_samples.py <outdir>   # writes sample files (never the EICAR string)
```

## Known limitations
- The dev `eicar` scanner only recognises the EICAR test file in **raw bytes**; compressed content is invisible to it. Real coverage needs ClamAV, which has **not** been run against this service yet.
- OCR needs Tesseract, which has **not** been run against this service yet (without it, images are blocked).
- Visually hidden text in PDFs is extracted but not identified as hidden (unlike DOCX).
- A PDF scan takes about 3 s (child process spawn plus parser import).
- Images with no recognised text are allowed with an `ocr_no_text` finding; text hidden in image pixels that OCR cannot read is not seen.
- Host antivirus can reset loopback connections that carry the EICAR string, so EICAR is tested in-process rather than over sockets.
