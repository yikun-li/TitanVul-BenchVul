"""
Anthropic API client for the Vulnerability Pipeline.

This module provides the Anthropic-specific implementation of the API client,
handling authentication, request formatting, and response processing for Claude models.
"""

from typing import List, Dict, Optional
from anthropic import Anthropic

from api.base_client import BaseAPIClient


class AnthropicClient(BaseAPIClient):
    """
    Anthropic API client implementation.
    
    Handles communication with the Anthropic API for Claude models,
    including message format conversion from OpenAI format to Anthropic format.
    """

    def __init__(
            self,
            api_key: str,
            model: str = "claude-3-5-sonnet-20241022",
            temperature: float = 0.7,
            max_tokens: int = 4000,
            base_url: Optional[str] = None
    ):
        """
        Initialize the Anthropic client.
        
        Args:
            api_key: Anthropic API key
            model: Model name to use (default: claude-3-sonnet-20240229)
            temperature: Temperature for text generation
            max_tokens: Maximum tokens to generate
            base_url: Custom base URL for API (optional)
            
        Raises:
            ValueError: If API key is not provided
        """
        if not api_key:
            raise ValueError("Anthropic API key is required")

        super().__init__(model, temperature, max_tokens)

        # Initialize Anthropic client
        kwargs = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url

        self.client = Anthropic(**kwargs)

        self.logger.info(f"Successfully initialized Anthropic client with model: {self.model}")

    def call_model(self, messages: List[Dict[str, str]], role_name: str) -> str:
        """
        Make a call to the Anthropic API.
        
        Args:
            messages: List of messages in OpenAI format (will be converted)
            role_name: Name of the role/agent making the call
            
        Returns:
            Response content as string
            
        Raises:
            Exception: If the API call fails
        """
        try:
            self.log_api_call(role_name)

            # Convert OpenAI format messages to Anthropic format
            system_message, anthropic_messages = self._convert_messages(messages)

            # Make the API call
            response = self.client.messages.create(
                model=self.model,
                system=system_message,
                messages=anthropic_messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens
            )

            content = response.content[0].text
            self.log_api_response(role_name)

            return content

        except Exception as e:
            self.handle_api_error(e, role_name)

    def _convert_messages(self, messages: List[Dict[str, str]]) -> tuple[Optional[str], List[Dict[str, str]]]:
        """
        Convert OpenAI format messages to Anthropic format.
        
        Anthropic expects:
        - A separate system message parameter
        - Only user/assistant messages in the messages list
        
        Args:
            messages: Messages in OpenAI format
            
        Returns:
            Tuple of (system_message, anthropic_messages)
        """
        system_message = None
        anthropic_messages = []

        for msg in messages:
            if msg["role"] == "system":
                system_message = msg["content"]
            elif msg["role"] in ["user", "assistant"]:
                anthropic_messages.append({
                    "role": msg["role"],
                    "content": msg["content"]
                })
            else:
                # Skip unknown roles
                self.logger.warning(f"Skipping message with unknown role: {msg['role']}")

        return system_message, anthropic_messages

    def validate_connection(self) -> bool:
        """
        Validate that the Anthropic client can connect to the API.
        
        Returns:
            True if connection is successful, False otherwise
        """
        try:
            # Make a simple API call to test connection
            response = self.client.messages.create(
                model=self.model,
                system="You are a helpful assistant.",
                messages=[{"role": "user", "content": "Hello"}],
                max_tokens=10,
                temperature=0
            )

            # If we get here without exception, connection is working
            self.logger.info("Anthropic API connection validated successfully")
            return True

        except Exception as e:
            self.logger.error(f"Anthropic API connection validation failed: {str(e)}")
            return False

    def format_messages(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Format messages for Anthropic API.
        
        This method returns the original messages since the conversion
        is handled internally in call_model.
        
        Args:
            messages: Raw messages in OpenAI format
            
        Returns:
            Original messages (conversion happens in call_model)
        """
        return messages

    def get_model_info(self) -> Dict[str, str]:
        """
        Get information about the current model.
        
        Returns:
            Dictionary containing model information
        """
        return {
            "provider": "Anthropic",
            "model": self.model,
            "temperature": str(self.temperature),
            "max_tokens": str(self.max_tokens)
        }

    def count_tokens(self, text: str) -> int:
        """
        Estimate token count for the given text.
        
        This is a rough estimate. Anthropic provides their own
        token counting tools for more accurate counts.
        
        Args:
            text: Text to count tokens for
            
        Returns:
            Estimated token count
        """
        # Rough estimate: ~4 characters per token for English text
        return len(text) // 4
