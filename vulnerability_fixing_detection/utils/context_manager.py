"""
Context management utilities for the Vulnerability Pipeline.

This module handles the management of application contexts,
language selection, and context uniqueness across pipeline runs.
"""

import random
from typing import Dict, List, Any

from utils.logging_utils import get_logger

logger = get_logger(__name__)


class ContextManager:
    """Manages application contexts and ensures uniqueness across generations."""

    def __init__(self, languages: List[str], language_weights: Dict[str, int], max_contexts: int = 30):
        """
        Initialize the context manager.
        
        Args:
            languages: List of available programming languages
            language_weights: Weights for language selection
            max_contexts: Maximum number of contexts to maintain
        """
        self.languages = languages
        self.language_weights = language_weights
        self.max_contexts = max_contexts
        self.previous_contexts = []

    def load_previous_contexts(self, contexts: List[Dict[str, Any]]) -> None:
        """
        Load previously generated contexts with FIFO strategy.
        
        Args:
            contexts: List of previously generated contexts
        """
        if len(contexts) > self.max_contexts:
            logger.info(f"Limiting previous contexts to {self.max_contexts} most recent (FIFO strategy)")
            self.previous_contexts = contexts[-self.max_contexts:]
        else:
            self.previous_contexts = contexts

        logger.info(f"Loaded {len(self.previous_contexts)} previously generated contexts.")

    def add_context(self, context: Dict[str, Any]) -> None:
        """
        Add a new context while maintaining the max_contexts limit (FIFO).
        
        Args:
            context: New context to add
        """
        if len(self.previous_contexts) >= self.max_contexts:
            # Remove the oldest context (first in the list)
            self.previous_contexts.pop(0)
            logger.info("Removed oldest context due to max_contexts limit")

        # Store the new context
        self.previous_contexts.append(context)
        logger.info(f"Added new context. Current context count: {len(self.previous_contexts)}/{self.max_contexts}")

    def select_programming_language(self) -> str:
        """
        Choose a programming language for the technology stack based on weights.
        
        Returns:
            Selected programming language
        """
        languages = list(self.language_weights.keys())
        weights = list(self.language_weights.values())

        # Select a language
        language = random.choices(languages, weights=weights, k=1)[0]

        # If "Other" is selected, choose a random language
        if language == "Other":
            return "Random Programming Language"

        logger.info(f"Selected programming language: {language}")
        return language

    def get_previous_contexts_summary(self) -> str:
        """
        Create a summary of previous contexts to avoid duplication.
        
        Returns:
            Formatted summary of previous contexts
        """
        if not self.previous_contexts:
            return "No previous contexts have been generated yet."

        summary = "Previously generated application contexts:\n"
        for i, context in enumerate(self.previous_contexts, 1):
            app_context = context['application_context']
            # Safely truncate description
            description = app_context['description']
            truncated_desc = description[:100] + "..." if len(description) > 100 else description

            summary += (
                f"\nApplication {i}:\n"
                f"Name: {app_context['name']}\n"
                f"Technologies: {', '.join(app_context['technology_stack'])}\n"
                f"Description: {truncated_desc}\n"
            )

        return summary

    def ensure_uniqueness(self, new_context: Dict[str, Any]) -> bool:
        """
        Check if a new context is sufficiently unique compared to previous ones.
        
        This is a basic uniqueness check based on application name and technology stack.
        In a production system, you might want more sophisticated similarity checking.
        
        Args:
            new_context: New context to check for uniqueness
            
        Returns:
            True if the context is unique enough, False otherwise
        """
        if not self.previous_contexts:
            return True

        new_app = new_context.get('application_context', {})
        new_name = new_app.get('name', '').lower()
        new_techs = set(tech.lower() for tech in new_app.get('technology_stack', []))

        for prev_context in self.previous_contexts:
            prev_app = prev_context.get('application_context', {})
            prev_name = prev_app.get('name', '').lower()
            prev_techs = set(tech.lower() for tech in prev_app.get('technology_stack', []))

            # Check for exact name match
            if new_name == prev_name:
                logger.warning(f"Duplicate application name detected: {new_name}")
                return False

            # Check for very similar technology stacks (>80% overlap)
            if len(new_techs) > 0 and len(prev_techs) > 0:
                overlap = len(new_techs.intersection(prev_techs))
                similarity = overlap / max(len(new_techs), len(prev_techs))
                if similarity > 0.8:
                    logger.warning(f"Very similar technology stack detected (similarity: {similarity:.2f})")
                    return False

        return True

    def get_context_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the current contexts.
        
        Returns:
            Dictionary containing context statistics
        """
        if not self.previous_contexts:
            return {"total_contexts": 0}

        # Count languages used
        language_counts = {}
        tech_counts = {}

        for context in self.previous_contexts:
            app_context = context.get('application_context', {})

            # Count primary languages
            primary_lang = app_context.get('primary_language', 'Unknown')
            language_counts[primary_lang] = language_counts.get(primary_lang, 0) + 1

            # Count technologies
            for tech in app_context.get('technology_stack', []):
                tech_counts[tech] = tech_counts.get(tech, 0) + 1

        return {
            "total_contexts": len(self.previous_contexts),
            "language_distribution": language_counts,
            "top_technologies": dict(sorted(tech_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "max_contexts": self.max_contexts
        }
