"""
LLM Package
NVIDIA NIM LLaMA API integration.

Components:
- NVIDIAClient  → Raw requests-based API client (no SDK)
- PromptBuilder → XML-structured prompt construction
"""

from backend.llm.nvidia_client import NVIDIAClient, nvidia_client
from backend.llm.prompt_builder import PromptBuilder

__all__ = ["NVIDIAClient", "nvidia_client", "PromptBuilder"]