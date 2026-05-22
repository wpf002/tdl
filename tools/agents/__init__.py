"""Per-language SIEM specialist agents.

Each of the 10 SIEM query languages has its own specialist agent that knows
only its own language deeply. The AgentOrchestrator runs them in parallel to
generate, validate, and improve the queries on a TDL rule.

Public surface:
    from tools.agents import AGENTS, get_agent, AgentOrchestrator
"""

from tools.agents.base_agent import BaseQueryAgent
from tools.agents.spl_agent import SPLAgent
from tools.agents.kql_agent import KQLAgent
from tools.agents.aql_agent import AQLAgent
from tools.agents.yara_l_agent import YaraLAgent
from tools.agents.esql_agent import ESQLAgent
from tools.agents.leql_agent import LEQLAgent
from tools.agents.crowdstrike_agent import CrowdStrikeAgent
from tools.agents.xql_agent import XQLAgent
from tools.agents.lucene_agent import LuceneAgent
from tools.agents.sumo_agent import SumoAgent
from tools.agents.orchestrator import AgentOrchestrator

# Ordered to match QUERY_KEYS across the codebase.
_AGENT_CLASSES = [
    SPLAgent, KQLAgent, AQLAgent, YaraLAgent, ESQLAgent,
    LEQLAgent, CrowdStrikeAgent, XQLAgent, LuceneAgent, SumoAgent,
]

AGENTS = {cls.LANGUAGE_KEY: cls() for cls in _AGENT_CLASSES}


def get_agent(language_key: str) -> BaseQueryAgent:
    """Return the singleton specialist agent for a language key, or raise KeyError."""
    return AGENTS[language_key]


__all__ = [
    "BaseQueryAgent", "AgentOrchestrator", "AGENTS", "get_agent",
    "SPLAgent", "KQLAgent", "AQLAgent", "YaraLAgent", "ESQLAgent",
    "LEQLAgent", "CrowdStrikeAgent", "XQLAgent", "LuceneAgent", "SumoAgent",
]
