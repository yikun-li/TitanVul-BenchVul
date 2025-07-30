"""
Agent package for the Vulnerability Pipeline.

This package contains the individual agents that handle different aspects
of the vulnerability generation pipeline. Each agent is responsible for
a specific task in the overall workflow.

Agents:
- ContextThreatModeler: Generates application contexts and identifies attack vectors
- VulnerableImplementer: Creates vulnerable code implementations
- SecurityAuditor: Analyzes vulnerabilities and implements fixes
- SecurityReviewer: Reviews and verifies the effectiveness of remediation
"""

from .context_threat_modeler import ContextThreatModeler
from .vulnerable_implementer import VulnerableImplementer
from .security_auditor import SecurityAuditor
from .security_reviewer import SecurityReviewer

__all__ = [
    "ContextThreatModeler",
    "VulnerableImplementer",
    "SecurityAuditor",
    "SecurityReviewer"
]
