"""
Security Review Agent for the Vulnerability Pipeline.

This agent (Agent 4) compares original vulnerable code with remediated code
to verify fixes and assess the effectiveness of the remediation process.
"""

import json
import re
from typing import Dict, Any, List

from api.base_client import BaseAPIClient
from utils.logging_utils import LoggerMixin


class SecurityReviewer(LoggerMixin):
    """
    Agent responsible for security review and remediation verification.
    
    This agent compares vulnerable and remediated code to assess
    the effectiveness of security fixes and validate remediation success.
    """

    def __init__(self, api_client: BaseAPIClient):
        """
        Initialize the Security Review agent.
        
        Args:
            api_client: API client for making model calls
        """
        self.api_client = api_client

    def review_remediation(
            self,
            vulnerable_code: str,
            remediation_data: Dict[str, str],
            vulnerability_type: str
    ) -> Dict[str, Any]:
        """
        Compare original vulnerable code with remediated code to verify fixes.
        
        Args:
            vulnerable_code: Vulnerable code from the Vulnerable Implementer
            remediation_data: Output from the Security Auditor (dictionary with remediated code)
            vulnerability_type: The type of vulnerability being analyzed
            
        Returns:
            Dictionary containing the security review assessment in JSON format
        """
        # Extract the remediated code from the remediation_data dictionary
        remediated_code = remediation_data.get("Remediated Code", "")
        if not remediated_code:
            self.logger.warning("Remediated code not found in remediation data, using empty string")

        # Analyze both code snippets
        vulnerable_analysis = self._analyze_code_snippet(vulnerable_code, "Vulnerable Code", vulnerability_type)
        remediated_analysis = self._analyze_code_snippet(remediated_code, "Remediated Code", vulnerability_type)

        # Combine results and assess remediation success
        review_data = {
            "vulnerable_code_analysis": vulnerable_analysis,
            "remediated_code_analysis": remediated_analysis,
            "vulnerability_type": vulnerability_type,
            "remediation_successful": self._assess_remediation_success(vulnerable_analysis, remediated_analysis)
        }

        return review_data

    def _analyze_code_snippet(self, code: str, code_type: str, vulnerability_type: str) -> Dict[str, Any]:
        """
        Analyze a single code snippet for vulnerabilities.
        
        Args:
            code: Code snippet to analyze
            code_type: Type description for logging ("Vulnerable Code" or "Remediated Code")
            vulnerability_type: The target vulnerability type to check for
            
        Returns:
            Dictionary containing analysis results
        """
        # Create the analysis prompt
        prompt = f"""
Analyze the following code for vulnerabilities:

```
{code}
```

Answer these questions with yes or no:
1. Does the code have a '{vulnerability_type}' vulnerability?
2. Is the syntax of the code correct?

Format your response in JSON:
{{
    "has_target_vulnerability": true/false,
    "is_syntax_correct": true/false
}}
"""

        messages = [
            {"role": "system", "content": """You are an expert Security Reviewer. Your task is to analyze code 
            for vulnerabilities and provide detailed security assessments."""},
            {"role": "user", "content": prompt}
        ]

        # Make the API call
        response = self.api_client.call_model(messages, f"Security Reviewer - {code_type}")

        # Parse the JSON response
        analysis_data = self._parse_analysis_response(response, code_type)

        return analysis_data

    def _parse_analysis_response(self, response: str, code_type: str) -> Dict[str, Any]:
        """
        Parse the analysis response and extract JSON data.
        
        Args:
            response: Raw response from the API
            code_type: Type of code being analyzed (for error reporting)
            
        Returns:
            Parsed analysis data
        """
        try:
            # Try to parse as direct JSON first
            analysis_data = json.loads(response)
            return analysis_data
        except json.JSONDecodeError:
            # Try to extract JSON from code blocks
            json_match = re.search(r'```json\n(.*?)\n```', response, re.DOTALL)
            if json_match:
                try:
                    analysis_data = json.loads(json_match.group(1))
                    return analysis_data
                except json.JSONDecodeError:
                    pass

            # Try to find JSON in curly braces
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                try:
                    analysis_data = json.loads(json_match.group(0))
                    return analysis_data
                except json.JSONDecodeError:
                    pass

            # If all parsing attempts fail, return default response
            self.logger.error(f"Could not parse JSON from {code_type} response. Raw response:")
            self.logger.error(response)

            # Return a default response if parsing fails - updated to match new prompt format
            analysis_data = {
                "has_target_vulnerability": True,  # Assume worst case
                "is_syntax_correct": False,  # Assume worst case
                "parse_error": f"Could not parse JSON response for {code_type}"
            }

            return analysis_data

    def _assess_remediation_success(
            self,
            vulnerable_analysis: Dict[str, Any],
            remediated_analysis: Dict[str, Any]
    ) -> bool:
        """
        Assess whether the remediation was successful.

        Args:
            vulnerable_analysis: Analysis results for the vulnerable code
            remediated_analysis: Analysis results for the remediated code

        Returns:
            True if remediation appears successful, False otherwise
        """
        # Check if the original code had the target vulnerability
        # and the remediated code does not
        original_has_vuln = vulnerable_analysis.get("has_target_vulnerability", True)
        fixed_has_vuln = remediated_analysis.get("has_target_vulnerability", True)

        # Also check if both code snippets have correct syntax
        original_syntax_correct = vulnerable_analysis.get("is_syntax_correct", False)
        fixed_syntax_correct = remediated_analysis.get("is_syntax_correct", False)

        # Remediation is considered successful if:
        # 1. The original code had the vulnerability
        # 2. The remediated code does not have the vulnerability
        # 3. The remediated code has correct syntax
        return original_has_vuln and not fixed_has_vuln and fixed_syntax_correct
