"""
Base API client for the Vulnerability Pipeline.

This module defines the abstract base class for all API clients,
ensuring consistent interface across different providers.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any

from utils.logging_utils import LoggerMixin


class BaseAPIClient(ABC, LoggerMixin):
    """
    Abstract base class for API clients.
    
    All API clients must implement the call_model method to ensure
    consistent interface across different providers.
    """

    def __init__(self, model: str, temperature: float = 0.7, max_tokens: int = 4000):
        """
        Initialize the base API client.
        
        Args:
            model: Model name to use
            temperature: Temperature for text generation
            max_tokens: Maximum tokens to generate
        """
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens

    @abstractmethod
    def call_model(self, messages: List[Dict[str, str]], role_name: str) -> str:
        """
        Make a call to the API and return the response content.
        
        Args:
            messages: List of messages in the conversation
            role_name: Name of the role/agent making the call (for logging)
            
        Returns:
            Response content as string
            
        Raises:
            Exception: If the API call fails
        """
        pass

    @abstractmethod
    def validate_connection(self) -> bool:
        """
        Validate that the API client can connect to the service.
        
        Returns:
            True if connection is successful, False otherwise
        """
        pass

    def format_messages(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Format messages for the specific API provider.
        
        This method can be overridden by subclasses if they need
        specific message formatting.
        
        Args:
            messages: Raw messages
            
        Returns:
            Formatted messages
        """
        return messages

    def handle_api_error(self, error: Exception, role_name: str) -> None:
        """
        Handle API errors consistently across providers.
        
        Args:
            error: The exception that occurred
            role_name: Name of the role/agent that encountered the error
        """
        self.logger.error(f"Error calling {role_name} via {self.__class__.__name__}: {str(error)}")

        # You could add retry logic, error categorization, etc. here
        # For now, we'll just re-raise the exception
        raise error

    def log_api_call(self, role_name: str) -> None:
        """
        Log the start of an API call.
        
        Args:
            role_name: Name of the role/agent making the call
        """
        provider_name = self.__class__.__name__.replace('Client', '')
        self.logger.info(f"Calling {role_name} using {provider_name} {self.model}...")

    def log_api_response(self, role_name: str) -> None:
        """
        Log the completion of an API call.
        
        Args:
            role_name: Name of the role/agent that completed the call
        """
        self.logger.info(f"{role_name} has responded.")
