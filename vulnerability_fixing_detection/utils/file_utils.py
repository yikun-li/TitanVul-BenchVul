"""
File utilities for the Vulnerability Pipeline.

This module provides utilities for file operations, result saving,
and progress tracking across pipeline runs.
"""

import os
import json
import time
import glob
from typing import Dict, Any, Set, Tuple, List, Optional

from utils.logging_utils import get_logger

logger = get_logger(__name__)


class FileManager:
    """Manages file operations for the vulnerability pipeline."""

    def __init__(self, output_dir: str = "_output"):
        """
        Initialize the file manager.
        
        Args:
            output_dir: Directory to store output files
        """
        self.output_dir = output_dir
        self.progress_file = os.path.join(output_dir, "generation_progress.json")

        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Output directory: {os.path.abspath(output_dir)}")

    def save_results(self, results: Dict[str, Any], output_file: Optional[str] = None) -> str:
        """
        Save pipeline results to JSON and Markdown files.
        
        Args:
            results: Results dictionary from pipeline execution
            output_file: Custom output filename (optional)
            
        Returns:
            Path to the saved JSON file
        """
        # Generate filename if not provided
        if output_file is None:
            timestamp = int(time.time())
            cwe_id = results['cwe_id']
            output_file = f"{cwe_id}_vulnerability_analysis_{timestamp}.json"

        # Ensure the path is within the output directory
        json_path = os.path.join(self.output_dir, output_file)

        # Save JSON file
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        logger.info(f"Results saved to {json_path}")

        # Save Markdown version for better readability
        md_path = json_path.replace('.json', '.md')
        self._save_markdown_report(results, md_path)
        logger.info(f"Markdown report saved to {md_path}")

        return json_path

    def _save_markdown_report(self, results: Dict[str, Any], md_path: str) -> None:
        """
        Save a markdown version of the results for better readability.
        
        Args:
            results: Results dictionary from pipeline execution
            md_path: Path to save the markdown file
        """
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(f"# {results['cwe_id']}: {results['vulnerability_type']} Analysis\n\n")

            # Application Context
            f.write("## Application Context\n\n")
            app_context = results['context_and_attack_vectors']['application_context']
            f.write(f"**Name**: {app_context['name']}\n\n")
            f.write(f"**Description**: {app_context['description']}\n\n")

            # Include primary language in the markdown report
            primary_language = app_context.get('primary_language', 'Not specified')
            f.write(f"**Primary Language**: {primary_language}\n\n")

            # Technology Stack
            f.write("### Technology Stack\n\n")
            for tech in app_context['technology_stack']:
                f.write(f"- {tech}\n")
            f.write("\n")

            # User Roles
            f.write("### User Roles\n\n")
            for role in app_context['user_roles']:
                f.write(f"- {role}\n")
            f.write("\n")

            # Attack Vector
            f.write("## Attack Vector\n\n")
            vector = results['context_and_attack_vectors']['attack_vectors'][0]
            f.write(f"### {vector['name']}\n\n")
            f.write(f"**Description**: {vector['description']}\n\n")
            f.write(f"**Impact**: {vector['impact']}\n\n")
            f.write(f"**Likelihood**: {vector['likelihood']}\n\n")

            # Vulnerable Code
            f.write("## Vulnerable Code\n\n")
            f.write("```\n")
            f.write(results['vulnerable_code'])
            f.write("\n```\n\n")

            # Remediation Data
            for section, content in results['remediation_data'].items():
                f.write(f"## {section}\n\n")
                f.write(content)
                f.write("\n\n")

            # Security Review
            f.write("## Security Review\n\n")
            security_review = results['security_review']

            f.write("### Vulnerability Assessment\n\n")
            f.write(
                f"**Original Code Contains Vulnerability ({results['vulnerability_type']})**: "
                f"{security_review['vulnerable_code_analysis'].get('has_target_vulnerability', 'Unknown')}\n\n"
            )
            f.write(
                f"**Fixed Code Contains Vulnerability**: "
                f"{security_review['remediated_code_analysis'].get('has_target_vulnerability', 'Unknown')}\n\n"
            )
            f.write(
                f"**Remediation Successful**: "
                f"{security_review.get('remediation_successful', 'Unknown')}\n\n"
            )

    def save_combined_results(self, all_results: List[Dict[str, Any]]) -> str:
        """
        Save all results to a combined JSON file.
        
        Args:
            all_results: List of all pipeline results
            
        Returns:
            Path to the combined results file
        """
        timestamp = int(time.time())
        combined_path = os.path.join(self.output_dir, f"all_vulnerability_samples_{timestamp}.json")

        with open(combined_path, 'w', encoding='utf-8') as f:
            json.dump(all_results, f, indent=2, ensure_ascii=False)

        logger.info(f"Combined results saved to {combined_path}")
        return combined_path

    def get_completed_samples(self) -> Set[Tuple[str, int]]:
        """
        Get a set of (cwe_id, sample_number) tuples that have already been generated.
        
        Returns:
            Set of tuples containing (cwe_id, sample_number)
        """
        completed_samples = set()

        # Get all JSON files in the output directory
        json_files = glob.glob(os.path.join(self.output_dir, "*.json"))

        # Skip the combined results file if it exists
        json_files = [f for f in json_files if "all_vulnerability_samples" not in f]

        for file_path in json_files:
            try:
                # Extract CWE ID and sample number from filename
                filename = os.path.basename(file_path)
                if filename.startswith("CWE-") and "_sample_" in filename:
                    parts = filename.split("_")
                    cwe_id = parts[0]  # e.g., "CWE-22"
                    sample_number = int(parts[2])  # e.g., sample number after "_sample_"
                    completed_samples.add((cwe_id, sample_number))
            except Exception as e:
                logger.warning(f"Failed to parse sample info from {file_path}: {str(e)}")
                continue

        logger.info(f"Found {len(completed_samples)} previously completed samples.")
        return completed_samples

    def save_progress(self, progress_data: Dict[str, Any]) -> None:
        """
        Save progress information to track generation state.
        
        Args:
            progress_data: Dictionary containing progress information
        """
        with open(self.progress_file, 'w', encoding='utf-8') as f:
            json.dump(progress_data, f, indent=2)

    def load_progress(self) -> Optional[Dict[str, Any]]:
        """
        Load progress information from the progress file.
        
        Returns:
            Progress data if file exists, None otherwise
        """
        if not os.path.exists(self.progress_file):
            return None

        try:
            with open(self.progress_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading progress file: {str(e)}")
            return None

    def cleanup_progress(self) -> None:
        """Remove the progress file when generation is complete."""
        if os.path.exists(self.progress_file):
            os.remove(self.progress_file)
            logger.info("Progress file cleaned up.")

    def load_previous_contexts(self, max_contexts: int) -> List[Dict[str, Any]]:
        """
        Load previously generated application contexts from existing output files.
        
        Args:
            max_contexts: Maximum number of contexts to load (FIFO strategy)
            
        Returns:
            List of previously generated contexts
        """
        # Get all JSON files in the output directory
        json_files = glob.glob(os.path.join(self.output_dir, "*.json"))

        # Skip the combined results file if it exists
        json_files = [f for f in json_files if "all_vulnerability_samples" not in f]

        if not json_files:
            logger.info("No previous output files found. Starting fresh.")
            return []

        logger.info(f"Loading contexts from {len(json_files)} previous output files...")

        # Sort files by modification time (oldest first)
        json_files.sort(key=os.path.getmtime)

        # Temporary list to collect all contexts
        all_contexts = []

        for file_path in json_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                if isinstance(data, list):
                    # Handle combined results file
                    for item in data:
                        if 'context_and_attack_vectors' in item:
                            all_contexts.append(item['context_and_attack_vectors'])
                else:
                    # Handle individual sample file
                    if 'context_and_attack_vectors' in data:
                        all_contexts.append(data['context_and_attack_vectors'])
            except Exception as e:
                logger.warning(f"Failed to load contexts from {file_path}: {str(e)}")
                continue

        # Keep only the most recent contexts up to max_contexts (FIFO)
        if len(all_contexts) > max_contexts:
            logger.info(f"Limiting previous contexts to {max_contexts} most recent (FIFO strategy)")
            previous_contexts = all_contexts[-max_contexts:]
        else:
            previous_contexts = all_contexts

        logger.info(f"Loaded {len(previous_contexts)} previously generated contexts.")
        return previous_contexts
