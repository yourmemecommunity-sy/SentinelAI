"""Red-team harness: target guard, offline generator, scoring by tier, example sanitization, dataset round-trip."""
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("red_team", ROOT / "scripts" / "security" / "red_team.py")
rt = importlib.util.module_from_spec(spec)
sys.modules["red_team"] = rt
spec.loader.exec_module(rt)


@pytest.mark.parametrize("url", ["https://api.example.com", "http://10.0.0.5:4000", "http://169.254.169.254", "file:///etc"])
def test_only_the_local_sentinel_can_be_attacked(url):
    with pytest.raises(SystemExit, match="refusing to attack"):
        rt.check_target(url)


def test_local_targets_are_accepted():
    assert rt.check_target("http://127.0.0.1:4000/") == "http://127.0.0.1:4000"
    assert rt.check_target("http://api:4000") == "http://api:4000"


def test_offline_generator_is_deterministic_per_round_and_covers_every_category():
    for cat in rt.CATEGORIES:
        a = rt.offline_generate(cat, 5, 1)
        assert a == rt.offline_generate(cat, 5, 1) and len(a) == 5
        assert a != rt.offline_generate(cat, 5, 2)
    hindi = " ".join(t for _, t in rt.offline_generate("multilingual", 20, 1))
    assert any("ऀ" <= ch <= "ॿ" for ch in hindi)  # Devanagari present


def test_scoring_reads_the_tier_from_the_explanation():
    a = rt.score(rt.Attack("x", "direct_injection", "t", "text", "offline", 1),
                 {"decision": "BLOCK", "detections": [{"entity": "PROMPT_INJECTION"}],
                  "explanation": {"decided_by": "classifier", "tier": 2, "versions": {"engine": "e1"}}})
    assert a.blocked and a.decided_by == "classifier" and a.tier == 2 and a.entities == ["PROMPT_INJECTION"]
    s = rt.score(rt.Attack("y", "obfuscation", "t", "text", "offline", 1), {"decision": "MASK", "detections": []})
    assert s.blocked is False  # masked text still reaches the model: the attack slipped through
    e = rt.score(rt.Attack("z", "obfuscation", "t", "text", "offline", 1), {"decision": None, "error": "http_401"})
    assert e.blocked is False and e.decided_by == "error"


def test_examples_are_scrubbed_and_truncated():
    out = rt.sanitize_example("mail jane@corp.invalid or call 98765 43210 with token " + "A" * 40 + " " + "x " * 200)
    assert "jane@" not in out and "98765" not in out and "AAAA" not in out
    assert len(out) <= 200


def test_round_is_saved_versioned_and_reloaded(tmp_path, monkeypatch):
    monkeypatch.setattr(rt, "DATA_DIR", tmp_path)
    scan = lambda text: {"decision": "BLOCK" if "1gn0r3" in text else "ALLOW", "explanation": {"decided_by": "rules", "tier": 1}}
    attacks = rt.run_round(scan, "offline", 20, 1, None, ["obfuscation"])
    rt.save_round(1, attacks, {"generator": "offline-seed-v1"})
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["rounds"][0]["round"] == 1 and manifest["rounds"][0]["records"] == len(attacks)
    assert "NOT part of the evaluation gate" in manifest["description"]
    reloaded = rt.read_round(1)
    assert [a.id for a in reloaded] == [a.id for a in attacks]
    assert all(json.loads(line)["source"] == "synthetic" for line in (tmp_path / "round-001.jsonl").read_text("utf-8").splitlines())
    board = rt.scoreboard(1, "offline-seed-v1", attacks)
    assert "TOTAL" in board and "attack success rate" in board


def test_claude_generator_without_a_key_is_reported_blocked(monkeypatch, capsys):
    monkeypatch.setenv("SENTINEL_REDTEAM_API_KEY", "snl_test")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert rt.main(["--generator", "claude", "--no-save"]) == 3
    assert "blocked: no key" in capsys.readouterr().out
