"""
Configuration management for the Vulnerability Pipeline.

This module handles all configuration settings, environment variables,
and default values for the vulnerability generation pipeline.
"""

import os
from typing import Dict, List, Optional, Literal
from dataclasses import dataclass


@dataclass
class ModelConfig:
    """Configuration for model providers and their settings."""
    provider: Literal["openai", "anthropic"] = "openai"
    model: str = "gpt-4o"
    temperature: float = 0.7
    max_tokens: int = 4000


@dataclass
class PipelineConfig:
    """Configuration for the vulnerability pipeline."""
    output_dir: str = "_output"
    max_contexts: int = 30
    languages: List[str] = None
    target_count: int = 60
    multiplier: int = 1
    resume: bool = True

    def __post_init__(self):
        """Set default languages if none provided."""
        if self.languages is None:
            self.languages = [
                "Java", "Python", "C", "JavaScript",
                "C#", "C++", "PHP", "Ruby"
            ]


@dataclass
class APICredentials:
    """API credentials for different providers."""
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None

    def __post_init__(self):
        """Load API keys from environment variables if not provided."""
        if not self.openai_api_key:
            self.openai_api_key = os.environ.get("OPENAI_API_KEY")

        if not self.anthropic_api_key:
            self.anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY")


class VulnerabilityTypes:
    """Predefined vulnerability types and their descriptions."""

    # CWE ID to vulnerability type mapping
    VULNERABILITY_DICT = {
        "CWE-22": "Path Traversal",
        "CWE-77": "Command Injection",
        "CWE-79": "Cross-site Scripting",
        "CWE-89": "SQL Injection",
        "CWE-94": "Code Injection",
        "CWE-125": "Out-of-bounds Read",
        "CWE-787": "Out-of-bounds Write",
        "CWE-190": "Integer Overflow or Wraparound",
        "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor: "
                   "Insertion of Sensitive Information Into Sent Data / "
                   "Observable Discrepancy / "
                   "Generation of Error Message Containing Sensitive Information / "
                   "Exposure of Sensitive Information Due to Incompatible Policies / "
                   "Insertion of Sensitive Information Into Debugging Code / "
                   "Insertion of Sensitive Information into Log File / "
                   "Exposure of Private Personal Information to an Unauthorized Actor / "
                   "Exposure of Sensitive System Information to an Unauthorized Control Sphere / "
                   "Insertion of Sensitive Information into Externally-Accessible File or Directory / "
                   "Exposure of Sensitive System Information Due to Uncleared Debug Information / "
                   "Device Unlock Credential Sharing / "
                   "Debug Messages Revealing Unnecessary Information",
        "CWE-269": "Improper Privilege Management: "
                   "Execution with Unnecessary Privileges / "
                   "Incorrect Privilege Assignment / "
                   "Privilege Defined With Unsafe Actions / "
                   "Privilege Chaining / "
                   "Privilege Context Switching Error / "
                   "Privilege Dropping or Lowering Errors / "
                   "Incorrect Use of Privileged APIs",
        "CWE-306": "Missing Authentication for Critical Function",
        "CWE-798": "Use of Hard-coded Credentials",
        "CWE-352": "Cross-Site Request Forgery (CSRF)",
        "CWE-918": "Server-Side Request Forgery (SSRF)",
        "CWE-400": "Uncontrolled Resource Consumption: "
                   "Allocation of Resources Without Limits or Throttling / "
                   "Improper Restriction of Power Consumption",
        "CWE-416": "Use After Free",
        "CWE-434": "Unrestricted Upload of File with Dangerous Type",
        "CWE-476": "NULL Pointer Dereference",
        "CWE-502": "Deserialization of Untrusted Data",
        "CWE-862": "Missing Authorization",
        "CWE-863": "Incorrect Authorization",
    }

    # Language weights for random selection
    LANGUAGE_WEIGHTS = {
        "Java": 1,
        "Python": 1,
        "C": 1,
        "JavaScript": 1,
        "C#": 1,
        "C++": 1,
        "PHP": 1,
        "Ruby": 1,
        "Other": 1
    }


def load_config(
        provider: str = "openai",
        model: str = "gpt-4o",
        temperature: float = 0.7,
        output_dir: str = "_output",
        max_contexts: int = 30,
        target_count: int = 60,
        multiplier: int = 1,
        languages: Optional[List[str]] = None
) -> tuple[ModelConfig, PipelineConfig, APICredentials]:
    """
    Load and validate configuration from parameters and environment.
    
    Args:
        provider: Model provider ('openai' or 'anthropic')
        model: Model name to use
        temperature: Temperature for text generation
        output_dir: Directory for output files
        max_contexts: Maximum number of contexts to maintain
        target_count: Target number of samples per vulnerability type
        multiplier: Multiplier for sample generation
        languages: List of programming languages to use
        
    Returns:
        Tuple of (ModelConfig, PipelineConfig, APICredentials)
        
    Raises:
        ValueError: If required API keys are missing
    """
    # Create configuration objects
    model_config = ModelConfig(
        provider=provider,
        model=model,
        temperature=temperature
    )

    pipeline_config = PipelineConfig(
        output_dir=output_dir,
        max_contexts=max_contexts,
        languages=languages,
        target_count=target_count,
        multiplier=multiplier
    )

    api_credentials = APICredentials()

    # Validate API credentials based on provider
    if provider == "openai" and not api_credentials.openai_api_key:
        raise ValueError(
            "OpenAI API key is required. Please set OPENAI_API_KEY environment variable "
            "or provide it directly."
        )
    elif provider == "anthropic" and not api_credentials.anthropic_api_key:
        raise ValueError(
            "Anthropic API key is required. Please set ANTHROPIC_API_KEY environment variable "
            "or provide it directly."
        )

    return model_config, pipeline_config, api_credentials
