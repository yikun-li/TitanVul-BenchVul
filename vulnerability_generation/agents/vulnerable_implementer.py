"""
Vulnerable Code Implementation Agent for the Vulnerability Pipeline.

This agent (Agent 2) generates realistic vulnerable code implementations
based on application contexts and attack vectors. The code appears
legitimate and follows common patterns while containing exploitable vulnerabilities.
"""

import json
from typing import Dict, Any, List

from api.base_client import BaseAPIClient
from utils.logging_utils import LoggerMixin


class VulnerableImplementer(LoggerMixin):
    """
    Agent responsible for generating vulnerable code implementations.
    
    This agent creates realistic, self-contained functions that demonstrate
    specific vulnerability types within the context of the generated application.
    """

    def __init__(self, api_client: BaseAPIClient):
        """
        Initialize the Vulnerable Code Implementation agent.
        
        Args:
            api_client: API client for making model calls
        """
        self.api_client = api_client

    def generate_vulnerable_code(self, context_data: Dict[str, Any]) -> str:
        """
        Generate vulnerable code based on application context and attack vectors.
        
        Args:
            context_data: Output from the Context & Threat Modeler containing
                         application context and vulnerability information
                         
        Returns:
            String containing a vulnerable function implementation
        """
        # Format the context data for the prompt
        context_str = json.dumps(context_data, indent=2)

        # Create the prompt messages
        messages = self._create_prompt_messages(context_str)

        # Make the API call
        vulnerable_code = self.api_client.call_model(messages, "Vulnerable Function Generator")

        # Clean and validate the response
        cleaned_code = self._clean_code_response(vulnerable_code)

        return cleaned_code

    def _create_prompt_messages(self, context_str: str) -> List[Dict[str, str]]:
        """
        Create the prompt messages for generating vulnerable code.
        
        Args:
            context_str: JSON string representation of the context data
            
        Returns:
            List of messages for the API call
        """
        system_prompt = """You are an expert Software Developer who specializes in creating 
vulnerable code samples for educational purposes. Your task is to implement a SINGLE FUNCTION 
that demonstrates the specific vulnerability types identified in the attack vectors.

The function should:
1. Be completely self-contained and realistic
2. Contain subtle but exploitable vulnerabilities
3. Follow common programming patterns
4. Include helpful comments explaining implementation details and logic
5. Ensure comments document functionality only - do not reference, hint at, or draw attention to any vulnerabilities

Provide ONLY the vulnerable function with no additional explanations or surrounding code."""

        user_prompt = f"Create a single vulnerable function based on the following application context and attack vectors:\n\n{context_str}"

        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

    def _clean_code_response(self, code_response: str) -> str:
        """
        Clean the code response by removing unnecessary markup and formatting.
        
        Args:
            code_response: Raw code response from the API
            
        Returns:
            Cleaned code string
        """
        # Remove code block markers if present
        lines = code_response.strip().split('\n')

        # Remove markdown code block markers
        if lines and lines[0].startswith('```'):
            lines = lines[1:]
        if lines and lines[-1].startswith('```'):
            lines = lines[:-1]

        # Join the lines back together
        cleaned_code = '\n'.join(lines).strip()

        return cleaned_code
