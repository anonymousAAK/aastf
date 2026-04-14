"""
AASTF — Agentic AI Security Testing Framework

The first security testing framework that intercepts AI agent execution graphs
and tests them against the OWASP ASI Top 10 threat taxonomy.

    pip install aastf
    aastf run myapp.agent:create_agent --profile owasp-asi-top10

84.30% of production AI agents can be hijacked by adversarial input.
AASTF exists because that number needs to go to zero.
"""

__version__ = "0.1.0"
__author__ = "AASTF Contributors"
__license__ = "MIT"
