"""
Realistic Vulnerability Generation (RVG) Pipeline - A comprehensive system for generating vulnerable code samples.

This package provides a complete pipeline for generating realistic vulnerable code
samples across multiple programming languages and vulnerability types, with
automated remediation and security review capabilities.

Main Components:
    - Pipeline orchestrator for coordinating the entire process
    - Context and threat modeling agent
    - Vulnerable code implementation agent
    - Security auditing and remediation agent
    - Security review and verification agent
    - Support for multiple LLM providers (OpenAI, Anthropic)
    - Comprehensive logging and progress tracking
    - File management and result persistence
"""

from .pipeline import VulnerabilityPipeline
from .config.settings import (
    ModelConfig,
    PipelineConfig,
    APICredentials,
    VulnerabilityTypes,
    load_config
)

__all__ = [
    "VulnerabilityPipeline",
    "ModelConfig",
    "PipelineConfig",
    "APICredentials",
    "VulnerabilityTypes",
    "load_config",
]
