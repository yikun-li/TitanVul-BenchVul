"""
Security Auditing and Remediation Agent for the Vulnerability Pipeline.

This agent (Agent 3) analyzes vulnerable code and implements secure fixes.
It focuses on providing remediated versions of vulnerable code without
exposing detailed vulnerability information in its primary output.
"""

import json
from typing import Dict, Any, List

from api.base_client import BaseAPIClient
from utils.logging_utils import LoggerMixin


class SecurityAuditor(LoggerMixin):
    """
    Agent responsible for security analysis and code remediation.
    
    This agent analyzes vulnerable code and implements secure fixes,
    providing remediated versions that address the identified vulnerabilities.
    """

    def __init__(self, api_client: BaseAPIClient):
        """
        Initialize the Security Auditing and Remediation agent.
        
        Args:
            api_client: API client for making model calls
        """
        self.api_client = api_client

    def analyze_and_remediate(
            self,
            context_data: Dict[str, Any],
            vulnerable_code: str
    ) -> Dict[str, Any]:
        """
        Analyze vulnerabilities and implement fixes.
        
        Args:
            context_data: Output from the Context & Threat Modeler
            vulnerable_code: Vulnerable code from the Vulnerable Implementer
            
        Returns:
            Dictionary containing remediated code and analysis results
        """
        # Format the context for the prompt
        context_str = json.dumps(context_data, indent=2)

        # Create the prompt messages
        messages = self._create_prompt_messages(context_str, vulnerable_code)

        # Make the API call
        response = self.api_client.call_model(messages, "Security Auditor & Remediation Engineer")

        # Parse the response to extract different sections
        sections = self._parse_response_sections(response)

        return sections

    def _create_prompt_messages(self, context_str: str, vulnerable_code: str) -> List[Dict[str, str]]:
        """
        Create the prompt messages for security analysis and remediation.
        
        Args:
            context_str: JSON string representation of the context data
            vulnerable_code: The vulnerable code to analyze and fix
            
        Returns:
            List of messages for the API call
        """
        system_prompt = """You are an expert Security Auditor and Remediation Engineer. 
Your task is to:
1. Analyze the provided code for security vulnerabilities
2. Implement fixed versions of the vulnerable code

IMPORTANT: Provide ONLY the remediated code with NO explanations, analysis, or commentary.
DO NOT include any descriptions of the vulnerabilities or how they were fixed.
DO NOT include any section headers other than the one specified below.

## Remediated Code

[PASTE ONLY THE FIXED CODE HERE WITH NO ADDITIONAL TEXT]
"""

        user_prompt = (
            f"You are a secure coding assistant. Based on the provided CONTEXT, "
            f"analyze the VULNERABLE CODE below and return a revised version that is secure and "
            f"production-ready. "
            f"Make sure to fix **all known and potential vulnerabilities**, following best practices for "
            f"security and maintainability. "
            f"Include comments in the fixed code where changes were made, explaining what was insecure and "
            f"how it was fixed.\n\n"
            f"CONTEXT:\n{context_str}\n\n"
            f"VULNERABLE CODE:\n{vulnerable_code}"
        )

        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

    def _parse_response_sections(self, response: str) -> Dict[str, str]:
        """
        Parse the API response to extract different sections.
        
        Args:
            response: Raw response from the API
            
        Returns:
            Dictionary containing parsed sections
        """
        sections = {}
        current_section = None
        current_content = []

        for line in response.split('\n'):
            if line.startswith('## '):
                # Save previous section if it exists
                if current_section:
                    sections[current_section] = '\n'.join(current_content)

                # Start new section
                current_section = line[3:].strip()
                current_content = []
            elif current_section:
                current_content.append(line)

        # Save the last section
        if current_section:
            sections[current_section] = '\n'.join(current_content)

        # If no sections were found, treat the entire response as remediated code
        if not sections:
            sections['Remediated Code'] = response.strip()

        return sections
