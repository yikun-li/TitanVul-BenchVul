"""
API client package for the Vulnerability Pipeline.

This package provides unified interfaces for different AI model providers,
ensuring consistent behavior across OpenAI and Anthropic APIs.

Components:
- BaseAPIClient: Abstract base class defining the client interface
- OpenAIClient: Implementation for OpenAI GPT models
- AnthropicClient: Implementation for Anthropic Claude models

All clients implement the same interface, making it easy to switch between
providers or add new ones in the future.
"""

from .base_client import BaseAPIClient
from .openai_client import OpenAIClient
from .anthropic_client import AnthropicClient

__all__ = [
    "BaseAPIClient",
    "OpenAIClient",
    "AnthropicClient"
]
