"""Child-process targets used to simulate a parser that crashes or hangs. They live in a real importable module because
the isolation layer uses `spawn`, which re-imports the target by name in the child."""
import os
import time


def crash(conn, *args):          # simulates a segfault / hard abort inside a parser
    os._exit(3)


def hang(conn, *args):           # simulates an infinite loop / algorithmic-complexity attack
    time.sleep(120)


def raise_in_child(conn, *args):  # simulates an unexpected exception type escaping the parser
    conn.send(("error", "ZeroDivisionError"))
    conn.close()
