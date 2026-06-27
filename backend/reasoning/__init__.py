"""
Reasoning Engine Package
Extended thinking for multi-alert correlation.

Components:
- ChainCorrelator → Detect attack chains across multiple alerts
"""

from backend.reasoning.chain_correlator import ChainCorrelator

__all__ = ["ChainCorrelator"]