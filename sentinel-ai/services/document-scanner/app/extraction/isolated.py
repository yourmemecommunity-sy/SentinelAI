"""Run parsers in a separate process.

Parsers process attacker-controlled bytes. A bug (crash, infinite loop, memory blow-up, exploit) must not be able to
take down or stall the service, so each extraction runs in a fresh `spawn`ed child with a hard wall-clock limit. Any
timeout, crash or unexpected exit becomes a BLOCK. (On POSIX the child is additionally address-space limited; Windows has
no equivalent, so there the wall-clock limit and process isolation are the controls.)
"""
from __future__ import annotations

import multiprocessing as mp
from multiprocessing.connection import Connection

from app.models import Blocked, Finding
from app.parsers import Limits, extract

_MEMORY_LIMIT = 1024 * 1024 * 1024   # 1 GiB address space (POSIX only)


def _child(conn: Connection, kind: str, data: bytes, max_chars: int, max_pages: int) -> None:
    try:
        try:
            import resource  # POSIX only
            resource.setrlimit(resource.RLIMIT_AS, (_MEMORY_LIMIT, _MEMORY_LIMIT))
        except (ImportError, ValueError, OSError):
            pass
        text, findings, pages = extract(kind, data, Limits(max_chars, max_pages))
        conn.send(("ok", text, [f.model_dump() for f in findings], pages))
    except Blocked as b:
        conn.send(("blocked", b.reason, [f.model_dump() for f in b.findings]))
    except MemoryError:
        conn.send(("blocked", "memory_limit", []))
    except BaseException as e:  # noqa: BLE001 - the child must always answer
        conn.send(("error", type(e).__name__))
    finally:
        conn.close()


def run_isolated(kind: str, data: bytes, limits: Limits, timeout: float) -> tuple[str, list[Finding], int | None]:
    ctx = mp.get_context("spawn")
    parent, child = ctx.Pipe(duplex=False)
    proc = ctx.Process(target=_child, args=(child, kind, data, limits.max_text_chars, limits.max_pdf_pages), daemon=True)
    proc.start()
    child.close()
    try:
        if not parent.poll(timeout):
            raise Blocked("extraction_timeout", [Finding(type="extraction_timeout", severity="HIGH", detail="parser exceeded its time limit")])
        try:
            msg = parent.recv()
        except (EOFError, OSError):
            raise Blocked("extraction_crashed", [Finding(type="extraction_crashed", severity="HIGH", detail="parser process died")]) from None
    finally:
        parent.close()
        proc.join(1)
        if proc.is_alive():
            proc.kill()
            proc.join(2)

    if msg[0] == "ok":
        return msg[1], [Finding(**f) for f in msg[2]], msg[3]
    if msg[0] == "blocked":
        raise Blocked(msg[1], [Finding(**f) for f in msg[2]])
    raise Blocked(f"internal_error:{msg[1]}", [Finding(type="internal_error", severity="HIGH", detail="parser failed unexpectedly")])
