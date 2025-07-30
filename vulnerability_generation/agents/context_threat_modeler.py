"""
Context and Threat Modeling Agent for the Vulnerability Pipeline.

This agent (Agent 1) generates realistic application contexts and identifies
attack vectors based on specified vulnerability types. It ensures uniqueness
across generations and incorporates domain knowledge about various technologies.
"""

import json
import random
import re
from typing import Dict, Any, List

from api.base_client import BaseAPIClient
from utils.logging_utils import LoggerMixin


class ContextThreatModeler(LoggerMixin):
    """
    Agent responsible for generating application contexts and threat models.
    
    This agent creates unique, realistic application scenarios and identifies
    specific attack vectors for given vulnerability types.
    """

    def __init__(self, api_client: BaseAPIClient):
        """
        Initialize the Context and Threat Modeling agent.
        
        Args:
            api_client: API client for making model calls
        """
        self.api_client = api_client

    def generate_context_and_threats(
            self,
            vulnerability_type: str,
            selected_language: str,
            previous_contexts_summary: str
    ) -> Dict[str, Any]:
        """
        Generate application context and identify attack vectors.
        
        Args:
            vulnerability_type: The type of vulnerability to focus on
            selected_language: Primary programming language for the application
            previous_contexts_summary: Summary of previously generated contexts
            
        Returns:
            Dictionary containing application context and attack vectors
            
        Raises:
            ValueError: If the response cannot be parsed as valid JSON
        """
        # Handle vulnerability types with subtypes
        chosen_vulnerability = self._process_vulnerability_type(vulnerability_type)

        # Create the prompt messages
        messages = self._create_prompt_messages(
            chosen_vulnerability,
            selected_language,
            previous_contexts_summary
        )

        # Log the chosen vulnerability for tracking
        self.logger.info(f"Chosen vulnerability: {chosen_vulnerability}")

        # Make the API call
        response = self.api_client.call_model(messages, "Context & Threat Modeler")

        # Parse and validate the response
        context_data = self._parse_response(response)

        # Ensure attack_vectors is in list format for backward compatibility
        if isinstance(context_data.get('attack_vectors'), dict):
            context_data['attack_vectors'] = [context_data['attack_vectors']]

        return context_data

    def _process_vulnerability_type(self, vulnerability_type: str) -> str:
        """
        Process vulnerability type to handle subtypes.
        
        If the vulnerability type contains subtypes (separated by '/'),
        randomly choose one specific subtype to focus on.
        
        Args:
            vulnerability_type: Raw vulnerability type string
            
        Returns:
            Processed vulnerability type (specific subtype if applicable)
        """
        if ":" in vulnerability_type:
            main_type, subtypes = vulnerability_type.split(":", 1)
            # Clean and split the subtypes
            subtype_list = [s.strip() for s in subtypes.split("/")]
            # Randomly choose one subtype
            chosen_vulnerability = f"{main_type}: {random.choice(subtype_list)}"
        else:
            chosen_vulnerability = vulnerability_type

        return chosen_vulnerability

    def _create_prompt_messages(
            self,
            vulnerability_type: str,
            selected_language: str,
            previous_contexts_summary: str
    ) -> List[Dict[str, str]]:
        """
        Create the prompt messages for the API call.
        
        Args:
            vulnerability_type: Processed vulnerability type
            selected_language: Primary programming language
            previous_contexts_summary: Summary of previous contexts
            
        Returns:
            List of messages for the API call
        """
        system_prompt = f"""You are an expert Application Security Threat Modeler. 
Your task is to create a realistic application context and identify ONE potential attack vector 
based on a specified vulnerability type. Be specific and detailed in your analysis.

IMPORTANT REQUIREMENTS:
1. Create a completely unique application that is different from all previous examples
2. Use a distinct technology stack that hasn't been overused
3. Design different user roles and functionality
4. Ensure the application name is unique and descriptive
5. Provide only ONE attack vector focused on the specified vulnerability type
6. If the vulnerability type includes subtypes (separated by '/'), focus on the specific subtype provided
7. Use {selected_language} as the primary programming language for this application

Here are the previous contexts that have already been generated:
{previous_contexts_summary}

Provide your response in the following JSON format:
{{
    "application_context": {{
        "name": "Unique name of the application",
        "description": "Brief description of the application",
        "primary_language": "{selected_language}",
        "technology_stack": ["List", "of", "technologies"],
        "user_roles": ["List", "of", "user", "roles"]
    }},
    "attack_vectors": {{
        "name": "Name of attack vector",
        "description": "Description of how the attack could be executed",
        "impact": "Potential impact if exploited",
        "likelihood": "Likelihood of exploitation (High/Medium/Low)"
    }}
}}"""

        user_prompt = f"""Generate a completely new and unique application context and identify ONE attack vector for:
{vulnerability_type}.

Ensure the application is distinct from all previous examples listed above in:
1. Application name
2. Technology stack
3. Functionality
4. User roles

Use {selected_language} as the primary programming language for this application.
Focus on just one attack vector for the specified vulnerability type."""

        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ]

    def _parse_response(self, response: str) -> Dict[str, Any]:
        """
        Parse the API response and extract JSON data.
        
        Args:
            response: Raw response from the API
            
        Returns:
            Parsed JSON data as dictionary
            
        Raises:
            ValueError: If the response cannot be parsed as valid JSON
        """
        try:
            # Try to parse as direct JSON first
            context_data = json.loads(response)
            return context_data
        except json.JSONDecodeError:
            # If that fails, try to extract JSON from code blocks
            json_match = re.search(r'```json\n(.*?)\n```', response, re.DOTALL)
            if json_match:
                try:
                    context_data = json.loads(json_match.group(1))
                    return context_data
                except json.JSONDecodeError:
                    pass

            # If all parsing attempts fail, log and raise error
            self.logger.error("Could not parse JSON from response. Raw response:")
            self.logger.error(response)
            raise ValueError("Invalid JSON response from Context & Threat Modeler")
