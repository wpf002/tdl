#!/usr/bin/env python3
"""End-to-end integration test for the TDL Playbook app.

Starts the Flask backend in a subprocess, hits every /api/* endpoint, asserts
shape and counts. Verifies the Vite production build of the frontend is
sound. Exits non-zero on the first failure; cleans up child processes.
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PORT = int(os.environ.get("TEST_PORT", 8788))  # different from default to avoid clash
BASE = f"http://127.0.0.1:{PORT}"

GREEN = "\033[92m"
RED = "\033[91m"
DIM = "\033[2m"
RESET = "\033[0m"

failed: list[str] = []


def ok(msg: str) -> None:
    print(f"  {GREEN}✓{RESET} {msg}")


def fail(msg: str) -> None:
    failed.append(msg)
    print(f"  {RED}✗{RESET} {msg}")


def fetch(path: str, timeout: float = 30.0):
    req = urllib.request.Request(f"{BASE}{path}", headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def wait_for_ready(deadline_s: float = 20.0):
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        try:
            status, body = fetch("/api/health", timeout=2.0)
            if status == 200 and body.get("status") == "ok":
                return body
        except (urllib.error.URLError, ConnectionResetError, TimeoutError):
            time.sleep(0.25)
    raise RuntimeError("backend did not become ready within 20s")


def section(title: str) -> None:
    print(f"\n{DIM}── {title} ──{RESET}")


def main() -> int:
    print(f"\n{DIM}TDL Playbook — integration test{RESET}")
    print(f"{DIM}base: {BASE}{RESET}")

    # ── Phase 1: launch backend ──────────────────────────────────────────────
    section("backend boot")
    env = os.environ.copy()
    env["PORT"] = str(PORT)
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "tools" / "server.py")],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        cwd=ROOT,
        start_new_session=True,
    )
    try:
        try:
            health = wait_for_ready()
            ok(f"backend ready (health.rules = {health['rules']})")
        except Exception as e:
            fail(f"backend boot failed: {e}")
            try:
                logs = proc.stdout.read(2000).decode("utf-8", errors="replace") if proc.stdout else ""
                if logs:
                    print(f"{DIM}--- backend log ---{RESET}\n{logs}")
            except Exception:
                pass
            return 1

        # ── Phase 2: API endpoint contract ───────────────────────────────────
        section("api contracts")

        try:
            _, stats = fetch("/api/stats")
            assert stats["total"] == 700, f"expected 700, got {stats['total']}"
            assert len(stats["by_tactic"]) == 12
            assert set(stats["by_severity"]) >= {"Critical", "High", "Medium", "Low"}
            ok(f"GET /api/stats — total=700, 12 tactics, 4 severities")
        except Exception as e:
            fail(f"GET /api/stats: {e}")

        try:
            _, rules = fetch("/api/rules")
            assert isinstance(rules, list) and len(rules) == 700
            ids = {r["rule_id"] for r in rules}
            assert len(ids) == 700, "non-unique rule_ids"
            assert not any(rid.startswith("TDE-") for rid in ids), "found TDE- legacy IDs"
            sample = rules[0]
            for k in ("rule_id", "name", "tactic", "technique_id", "severity", "lifecycle", "queries"):
                assert k in sample, f"missing field: {k}"
            assert set(sample["queries"]) >= {"spl", "kql", "aql", "yara_l", "esql", "leql", "crowdstrike", "xql", "lucene"}
            ok("GET /api/rules — 700 unique, all 9 query languages present")
        except Exception as e:
            fail(f"GET /api/rules: {e}")

        try:
            _, filtered = fetch("/api/rules?tactic=Credential%20Access&severity=High")
            assert isinstance(filtered, list)
            assert all(r["tactic"] == "Credential Access" and r["severity"] == "High" for r in filtered)
            ok(f"GET /api/rules?tactic=Credential Access&severity=High — {len(filtered)} matches, filter correct")
        except Exception as e:
            fail(f"GET /api/rules (filter): {e}")

        try:
            _, q_search = fetch("/api/rules?q=kerberos")
            assert isinstance(q_search, list) and len(q_search) >= 1
            ok(f"GET /api/rules?q=kerberos — {len(q_search)} matches")
        except Exception as e:
            fail(f"GET /api/rules (search): {e}")

        try:
            sample_id = "TDL-CA-000019"
            _, rule = fetch(f"/api/rules/{sample_id}")
            assert rule["rule_id"] == sample_id
            ok(f"GET /api/rules/{sample_id} — full rule retrieved")
        except Exception as e:
            fail(f"GET /api/rules/<id>: {e}")

        try:
            try:
                fetch("/api/rules/DOES-NOT-EXIST")
                fail("GET /api/rules/<bogus> — expected 404, got 200")
            except urllib.error.HTTPError as he:
                assert he.code == 404
                ok("GET /api/rules/<bogus> — correctly returns 404")
        except Exception as e:
            fail(f"GET /api/rules/<bogus>: {e}")

        try:
            _, tactics = fetch("/api/tactics")
            assert isinstance(tactics, list) and len(tactics) == 12
            assert sum(t["count"] for t in tactics) == 700
            ok("GET /api/tactics — 12 tactics, counts sum to 700")
        except Exception as e:
            fail(f"GET /api/tactics: {e}")

        try:
            _, chains = fetch("/api/chains")
            assert isinstance(chains, list) and len(chains) == 5
            active = sum(1 for c in chains if c.get("active"))
            assert active == 5, f"expected 5 active chains, got {active}"
            ok(f"GET /api/chains — 5/5 chains active")
        except Exception as e:
            fail(f"GET /api/chains: {e}")

        try:
            _, cov = fetch("/api/coverage")
            assert isinstance(cov, dict)
            assert "by_tactic" in cov or "by_technique" in cov or "summary" in cov
            ok("GET /api/coverage — report served")
        except Exception as e:
            fail(f"GET /api/coverage: {e}")

        try:
            _, recs = fetch("/api/recommendations", timeout=60.0)
            assert recs is not None
            ok("GET /api/recommendations — engine ran, output served")
        except Exception as e:
            fail(f"GET /api/recommendations: {e}")

    finally:
        # ── Cleanup: kill backend ────────────────────────────────────────────
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass

    # ── Phase 3: frontend production build ───────────────────────────────────
    section("frontend build")
    if shutil.which("npm") is None:
        fail("npm not found")
    else:
        try:
            r = subprocess.run(
                ["npm", "run", "build"],
                cwd=ROOT / "ui",
                capture_output=True,
                text=True,
                timeout=120,
            )
            if r.returncode != 0:
                fail(f"ui build exited {r.returncode}: {r.stderr[-500:]}")
            else:
                dist_index = ROOT / "ui" / "dist" / "index.html"
                assert dist_index.exists(), "dist/index.html missing"
                bundle_glob = list((ROOT / "ui" / "dist" / "assets").glob("index-*.js"))
                assert bundle_glob, "no JS bundle produced"
                bundle_text = bundle_glob[0].read_text(encoding="utf-8", errors="replace")
                bundle_rule_count = bundle_text.count('rule_id:"')
                assert bundle_rule_count == 700, f"bundle has {bundle_rule_count} rule_ids, expected 700"
                ok(f"ui build — dist/index.html present, bundle inlines 700 rules")
        except subprocess.TimeoutExpired:
            fail("ui build timed out after 120s")
        except Exception as e:
            fail(f"ui build: {e}")

    # ── Summary ──────────────────────────────────────────────────────────────
    print()
    if failed:
        print(f"{RED}FAILED: {len(failed)} check(s){RESET}")
        for m in failed:
            print(f"  - {m}")
        return 1
    print(f"{GREEN}ALL CHECKS PASSED{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
