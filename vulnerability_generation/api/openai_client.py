"""
OpenAI API client for the Vulnerability Pipeline.

This module provides the OpenAI-specific implementation of the API client,
handling authentication, request formatting, and response processing.
"""

from typing import List, Dict, Optional
from openai import OpenAI

from api.base_client import BaseAPIClient


class OpenAIClient(BaseAPIClient):
    """
    OpenAI API client implementation.
    
    Handles communication with the OpenAI API using the official OpenAI Python client.
    """

    def __init__(
            self,
            api_key: str,
            model: str = "gpt-4o",
            temperature: float = 0.7,
            max_tokens: int = 4000,
            organization: Optional[str] = None,
            base_url: Optional[str] = None
    ):
        """
        Initialize the OpenAI client.
        
        Args:
            api_key: OpenAI API key
            model: Model name to use (default: gpt-4o)
            temperature: Temperature for text generation
            max_tokens: Maximum tokens to generate
            organization: OpenAI organization ID (optional)
            base_url: Custom base URL for API (optional)
            
        Raises:
            ValueError: If API key is not provided
        """
        if not api_key:
            raise ValueError("OpenAI API key is required")

        super().__init__(model, temperature, max_tokens)

        # Initialize OpenAI client
        self.client = OpenAI(
            api_key=api_key,
            organization=organization,
            base_url=base_url
        )

        self.logger.info(f"Successfully initialized OpenAI client with model: {self.model}")

    def call_model(self, messages: List[Dict[str, str]], role_name: str) -> str:
        """
        Make a call to the OpenAI API.
        
        Args:
            messages: List of messages in OpenAI format
            role_name: Name of the role/agent making the call
            
        Returns:
            Response content as string
            
        Raises:
            Exception: If the API call fails
        """
        try:
            self.log_api_call(role_name)

            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens
            )

            content = response.choices[0].message.content
            self.log_api_response(role_name)

            return content

        except Exception as e:
            self.handle_api_error(e, role_name)

    def validate_connection(self) -> bool:
        """
        Validate that the OpenAI client can connect to the API.
        
        Returns:
            True if connection is successful, False otherwise
        """
        try:
            # Make a simple API call to test connection
            test_messages = [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Hello"}
            ]

            response = self.client.chat.completions.create(
                model=self.model,
                messages=test_messages,
                max_tokens=10,
                temperature=0
            )

            # If we get here without exception, connection is working
            self.logger.info("OpenAI API connection validated successfully")
            return True

        except Exception as e:
            self.logger.error(f"OpenAI API connection validation failed: {str(e)}")
            return False

    def format_messages(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Format messages for OpenAI API.
        
        OpenAI uses the standard format, so no transformation needed.
        
        Args:
            messages: Raw messages
            
        Returns:
            Messages in OpenAI format
        """
        return messages

    def get_model_info(self) -> Dict[str, str]:
        """
        Get information about the current model.
        
        Returns:
            Dictionary containing model information
        """
        return {
            "provider": "OpenAI",
            "model": self.model,
            "temperature": str(self.temperature),
            "max_tokens": str(self.max_tokens)
        }

    def count_tokens(self, text: str) -> int:
        """
        Estimate token count for the given text.
        
        This is a rough estimate. For accurate token counting,
        you would need to use tiktoken library.
        
        Args:
            text: Text to count tokens for
            
        Returns:
            Estimated token count
        """
        # Rough estimate: ~4 characters per token for English text
        return len(text) // 4
