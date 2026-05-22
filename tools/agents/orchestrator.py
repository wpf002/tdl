"""AgentOrchestrator — fan out work across the 10 SIEM specialist agents.

Runs all agents in parallel with a ThreadPoolExecutor. Each per-agent call is
the network-bound Anthropic request, so threads (not processes) are the right
tool. Every method aggregates per-language usage into a `total` so callers can
log the full-run cost.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

QUERY_KEYS = ["spl", "kql", "aql", "yara_l", "esql", "leql",
              "crowdstrike", "xql", "lucene", "sumo"]

MAX_WORKERS = 10


def _zero_usage(language_key, model="claude-sonnet-4-5"):
    return {"language": language_key, "model": model,
            "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}


def _sum_usage(per_language_usage):
    """Roll up a list of per-agent usage dicts into one total usage dict."""
    total = {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0, "agents": 0}
    for u in per_language_usage:
        total["input_tokens"] += u.get("input_tokens", 0) or 0
        total["output_tokens"] += u.get("output_tokens", 0) or 0
        total["cost_usd"] += u.get("cost_usd", 0.0) or 0.0
        total["agents"] += 1
    total["cost_usd"] = round(total["cost_usd"], 6)
    return total


class AgentOrchestrator:
    def __init__(self, agents=None):
        # Imported lazily to avoid a circular import with the package __init__.
        if agents is None:
            from tools.agents import AGENTS
            agents = AGENTS
        self.agents = agents

    # ── generation ──
    def generate_all_queries(self, pseudo_logic, tactic, technique, platform, data_sources):
        """Run all 10 agents in parallel.

        Returns {"queries": {lang: query_str}, "usage": {lang: usage}, "total": {...}}.
        """
        queries, usage = {}, {}

        def _one(key):
            agent = self.agents[key]
            return key, agent.generate_query(pseudo_logic, tactic, technique, platform, data_sources)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = [ex.submit(_one, key) for key in self.agents]
            for fut in as_completed(futures):
                key, result = fut.result()
                queries[key] = result["query"]
                usage[key] = result["usage"]

        return {
            "queries": queries,
            "usage": usage,
            "total": _sum_usage(usage.values()),
        }

    # ── validation ──
    def validate_rule_queries(self, rule):
        """Validate each query on a rule with its language specialist, in parallel.

        Returns {"results": {lang: {valid, issues, score}}, "usage": {...},
                 "total": {...}, "overall_score": int}.
        """
        rule_queries = (rule or {}).get("queries") or {}
        pseudo_logic = (rule or {}).get("pseudo_logic") or ""

        results, usage = {}, {}

        def _one(key):
            agent = self.agents[key]
            return key, agent.validate_query(rule_queries.get(key), pseudo_logic)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = [ex.submit(_one, key) for key in self.agents]
            for fut in as_completed(futures):
                key, result = fut.result()
                u = result.pop("usage", _zero_usage(key))
                results[key] = result
                usage[key] = u

        scored = [r["score"] for r in results.values() if r.get("score") is not None]
        overall = round(sum(scored) / len(scored)) if scored else 0

        return {
            "results": results,
            "usage": usage,
            "total": _sum_usage(usage.values()),
            "overall_score": overall,
        }

    # ── improvement ──
    def improve_rule(self, rule, instruction):
        """Improve every query on a rule per an instruction, in parallel.

        Returns {"queries": {lang: improved_query}, "usage": {...}, "total": {...}}.
        """
        rule_queries = (rule or {}).get("queries") or {}
        pseudo_logic = (rule or {}).get("pseudo_logic") or ""

        queries, usage = {}, {}

        def _one(key):
            agent = self.agents[key]
            return key, agent.improve_query(rule_queries.get(key), pseudo_logic, instruction)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = [ex.submit(_one, key) for key in self.agents]
            for fut in as_completed(futures):
                key, result = fut.result()
                queries[key] = result["query"]
                usage[key] = result["usage"]

        return {
            "queries": queries,
            "usage": usage,
            "total": _sum_usage(usage.values()),
        }
