"""
Main Realistic Vulnerability Generation Pipeline (RVG).

This module orchestrates the entire vulnerability generation pipeline,
coordinating between all agents and managing the flow of data between components.
"""

import time
from typing import Dict, Any, List, Optional, Set, Tuple

from config.settings import ModelConfig, PipelineConfig, APICredentials, VulnerabilityTypes
from api.openai_client import OpenAIClient
from api.anthropic_client import AnthropicClient
from agents.context_threat_modeler import ContextThreatModeler
from agents.vulnerable_implementer import VulnerableImplementer
from agents.security_auditor import SecurityAuditor
from agents.security_reviewer import SecurityReviewer
from utils.file_utils import FileManager
from utils.context_manager import ContextManager
from utils.logging_utils import LoggerMixin


class VulnerabilityPipeline(LoggerMixin):
    """
    Main pipeline orchestrator for vulnerability generation.
    
    Coordinates the execution of all pipeline agents and manages
    the flow of data between components.
    """

    def __init__(
            self,
            model_config: ModelConfig,
            pipeline_config: PipelineConfig,
            api_credentials: APICredentials
    ):
        """
        Initialize the vulnerability pipeline.
        
        Args:
            model_config: Configuration for the model and API
            pipeline_config: Configuration for pipeline behavior
            api_credentials: API credentials for different providers
        """
        self.model_config = model_config
        self.pipeline_config = pipeline_config

        # Initialize API client based on provider
        self.api_client = self._initialize_api_client(model_config, api_credentials)

        # Initialize agents
        self.context_modeler = ContextThreatModeler(self.api_client)
        self.vulnerable_implementer = VulnerableImplementer(self.api_client)
        self.security_auditor = SecurityAuditor(self.api_client)
        self.security_reviewer = SecurityReviewer(self.api_client)

        # Initialize utilities
        self.file_manager = FileManager(pipeline_config.output_dir)
        self.context_manager = ContextManager(
            languages=pipeline_config.languages,
            language_weights=VulnerabilityTypes.LANGUAGE_WEIGHTS,
            max_contexts=pipeline_config.max_contexts
        )

        # Load previous contexts
        previous_contexts = self.file_manager.load_previous_contexts(pipeline_config.max_contexts)
        self.context_manager.load_previous_contexts(previous_contexts)

        self.logger.info(f"Pipeline initialized with {model_config.provider} provider and {model_config.model} model")

    def _initialize_api_client(self, model_config: ModelConfig, api_credentials: APICredentials):
        """
        Initialize the appropriate API client based on the provider.
        
        Args:
            model_config: Model configuration
            api_credentials: API credentials
            
        Returns:
            Initialized API client
            
        Raises:
            ValueError: If unsupported provider is specified
        """
        if model_config.provider == "openai":
            return OpenAIClient(
                api_key=api_credentials.openai_api_key,
                model=model_config.model,
                temperature=model_config.temperature,
                max_tokens=model_config.max_tokens
            )
        elif model_config.provider == "anthropic":
            return AnthropicClient(
                api_key=api_credentials.anthropic_api_key,
                model=model_config.model,
                temperature=model_config.temperature,
                max_tokens=model_config.max_tokens
            )
        else:
            raise ValueError(f"Unsupported model provider: {model_config.provider}")

    def run_single_sample(self, cwe_id: str, vulnerability_type: str) -> Dict[str, Any]:
        """
        Run the pipeline for a single vulnerability sample.
        
        Args:
            cwe_id: CWE identifier for the vulnerability
            vulnerability_type: Description of the vulnerability type
            
        Returns:
            Dictionary containing all pipeline outputs
        """
        self.logger.info(f"Starting pipeline for {cwe_id}: {vulnerability_type}")

        # Step 1: Generate context and attack vectors
        selected_language = self.context_manager.select_programming_language()
        previous_contexts_summary = self.context_manager.get_previous_contexts_summary()

        context_data = self.context_modeler.generate_context_and_threats(
            vulnerability_type=vulnerability_type,
            selected_language=selected_language,
            previous_contexts_summary=previous_contexts_summary
        )

        # Add the new context to the context manager
        self.context_manager.add_context(context_data)

        self.logger.info(f"Context & Attack Vectors Generated for {cwe_id}: {vulnerability_type}")

        # Step 2: Generate vulnerable code
        vulnerable_code = self.vulnerable_implementer.generate_vulnerable_code(context_data)
        self.logger.info("Vulnerable Code Generated")

        # Step 3: Analyze and fix vulnerabilities
        remediation_data = self.security_auditor.analyze_and_remediate(context_data, vulnerable_code)
        self.logger.info("Security Analysis and Remediation Completed")

        # Step 4: Verify fixes and provide final assessment
        security_review = self.security_reviewer.review_remediation(
            vulnerable_code, remediation_data, vulnerability_type
        )
        self.logger.info("Security Review Completed")

        # Compile all results
        results = {
            "cwe_id": cwe_id,
            "vulnerability_type": vulnerability_type,
            "context_and_attack_vectors": context_data,
            "vulnerable_code": vulnerable_code,
            "remediation_data": remediation_data,
            "security_review": security_review,
            "pipeline_metadata": {
                "model_provider": self.model_config.provider,
                "model": self.model_config.model,
                "temperature": self.model_config.temperature,
                "generation_timestamp": int(time.time()),
                "selected_language": selected_language
            }
        }

        return results

    def generate_samples(
            self,
            vulnerability_dict: Dict[str, str],
            n_samples: int = 1,
            resume: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Generate multiple vulnerability samples.
        
        Args:
            vulnerability_dict: Dictionary mapping CWE IDs to vulnerability descriptions
            n_samples: Number of samples to generate for each vulnerability type
            resume: Whether to resume from previous runs
            
        Returns:
            List of results dictionaries
        """
        all_results = []

        # Get already completed samples if resuming
        completed_samples = set()
        if resume:
            completed_samples = self.file_manager.get_completed_samples()
            if completed_samples:
                self.logger.info(f"Resuming generation. Skipping {len(completed_samples)} already completed samples.")

        total_to_generate = len(vulnerability_dict) * n_samples
        current_count = 0

        for cwe_id, vuln_type in vulnerability_dict.items():
            self.logger.info(f"\n{'=' * 50}")
            self.logger.info(f"Generating {n_samples} samples for {cwe_id}: {vuln_type}")
            self.logger.info(f"{'=' * 50}")

            for i in range(n_samples):
                sample_num = i + 1
                current_count += 1

                # Skip if this sample was already generated and we're resuming
                if resume and (cwe_id, sample_num) in completed_samples:
                    self.logger.info(f"Skipping already generated sample {sample_num}/{n_samples} for {cwe_id}")
                    continue

                self.logger.info(
                    f"Generating sample {sample_num}/{n_samples} for {cwe_id} ({current_count}/{total_to_generate})")

                try:
                    # Save progress before starting generation
                    self._save_progress(cwe_id, sample_num, n_samples, completed_samples)

                    # Run the pipeline for this sample
                    results = self.run_single_sample(cwe_id, vuln_type)
                    all_results.append(results)

                    # Save individual sample
                    timestamp = int(time.time())
                    output_filename = f"{cwe_id}_sample_{sample_num}_{timestamp}.json"
                    self.file_manager.save_results(results, output_filename)

                    # Update completed samples
                    completed_samples.add((cwe_id, sample_num))

                except Exception as e:
                    self.logger.error(f"Failed to generate sample {sample_num} for {cwe_id}: {str(e)}")
                    continue

        # Clean up progress file when done
        self.file_manager.cleanup_progress()

        return all_results

    def generate_needed_samples(
            self,
            vulnerability_dict: Dict[str, str],
            target_count: int = 100,
            current_counts: Optional[Dict[str, int]] = None,
            multiplier: int = 1,
            resume: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Generate additional samples to reach target counts with optional multiplier.
        
        Args:
            vulnerability_dict: Dictionary mapping CWE IDs to vulnerability descriptions
            target_count: Target number of samples for each vulnerability type
            current_counts: Current sample counts for each CWE
            multiplier: Multiplier for additional security samples
            resume: Whether to resume from previous runs
            
        Returns:
            List of results dictionaries
        """
        all_results = []

        # Get completed samples and current counts
        completed_samples = set()
        if resume:
            completed_samples = self.file_manager.get_completed_samples()

        if current_counts is None:
            current_counts = {}
            for cwe_id in vulnerability_dict.keys():
                cwe_samples = [(cwe, sample_num) for cwe, sample_num in completed_samples if cwe == cwe_id]
                current_counts[cwe_id] = len(cwe_samples)

        # Calculate and log totals
        total_base_needed = 0
        total_multiplied = 0
        for cwe_id, count in current_counts.items():
            if cwe_id in vulnerability_dict and count < target_count:
                base_needed = target_count - count
                multiplied = base_needed * multiplier
                total_base_needed += base_needed
                total_multiplied += multiplied

        self.logger.info(f"Target sample count per CWE: {target_count}")
        if multiplier > 1:
            self.logger.info(f"Using multiplier of {multiplier}x for additional security")
        self.logger.info(f"Total base samples needed: {total_base_needed}")
        self.logger.info(f"Total samples to generate: {total_multiplied}")

        # Generate samples for each CWE that needs more
        for cwe_id, vuln_type in vulnerability_dict.items():
            current_count = current_counts.get(cwe_id, 0)
            base_needed = max(0, target_count - current_count)
            needed_samples = base_needed * multiplier

            if needed_samples <= 0:
                self.logger.info(f"Skipping {cwe_id}: Already has {current_count} samples (target: {target_count})")
                continue

            self.logger.info(f"\n{'=' * 50}")
            self.logger.info(f"Generating {needed_samples} samples for {cwe_id}: {vuln_type}")
            self.logger.info(f"Current: {current_count}, Target: {target_count}, Base needed: {base_needed}")
            self.logger.info(f"{'=' * 50}")

            # Start sample numbering from current count + 1
            start_sample_num = current_count + 1

            for i in range(needed_samples):
                sample_num = start_sample_num + i

                # Skip if already generated
                if resume and (cwe_id, sample_num) in completed_samples:
                    self.logger.info(f"Skipping already generated sample {sample_num} for {cwe_id}")
                    continue

                self.logger.info(f"Generating sample {sample_num} for {cwe_id} ({i + 1}/{needed_samples})")

                try:
                    # Save progress
                    self._save_progress_needed(cwe_id, sample_num, target_count, current_counts, multiplier,
                                               completed_samples)

                    # Run the pipeline
                    results = self.run_single_sample(cwe_id, vuln_type)
                    all_results.append(results)

                    # Save individual sample
                    timestamp = int(time.time())
                    output_filename = f"{cwe_id}_sample_{sample_num}_{timestamp}.json"
                    self.file_manager.save_results(results, output_filename)

                    # Update completed samples
                    completed_samples.add((cwe_id, sample_num))

                except Exception as e:
                    self.logger.error(f"Failed to generate sample {sample_num} for {cwe_id}: {str(e)}")
                    continue

        # Clean up progress file
        self.file_manager.cleanup_progress()

        return all_results

    def _save_progress(self, cwe_id: str, sample_num: int, total_samples: int,
                       completed_samples: Set[Tuple[str, int]]) -> None:
        """Save progress for regular sample generation."""
        progress_data = {
            "current_cwe": cwe_id,
            "current_sample": sample_num,
            "timestamp": time.time(),
            "total_samples_per_cwe": total_samples,
            "completed_samples": len(completed_samples)
        }
        self.file_manager.save_progress(progress_data)

    def _save_progress_needed(
            self,
            cwe_id: str,
            sample_num: int,
            target_count: int,
            current_counts: Dict[str, int],
            multiplier: int,
            completed_samples: Set[Tuple[str, int]]
    ) -> None:
        """Save progress for needed sample generation."""
        progress_data = {
            "current_cwe": cwe_id,
            "current_sample": sample_num,
            "timestamp": time.time(),
            "total_samples_target": target_count,
            "current_counts": current_counts,
            "multiplier": multiplier,
            "completed_samples": len(completed_samples)
        }
        self.file_manager.save_progress(progress_data)

    def resume_from_progress(self, vulnerability_dict: Dict[str, str], n_samples: int = 1) -> List[Dict[str, Any]]:
        """
        Resume generation from a progress file if it exists.
        
        Args:
            vulnerability_dict: Dictionary mapping CWE IDs to vulnerability descriptions
            n_samples: Number of samples per vulnerability type
            
        Returns:
            List of results dictionaries
        """
        progress_data = self.file_manager.load_progress()

        if not progress_data:
            self.logger.info("No progress file found. Starting fresh generation.")
            return self.generate_samples(vulnerability_dict, n_samples, resume=True)

        current_cwe = progress_data.get("current_cwe")
        current_sample = progress_data.get("current_sample")

        if not current_cwe or not current_sample:
            self.logger.warning("Invalid progress file. Starting fresh generation.")
            return self.generate_samples(vulnerability_dict, n_samples, resume=True)

        self.logger.info(f"Resuming from progress file. Last processed: {current_cwe} sample {current_sample}")

        # Reorder vulnerability_dict to prioritize the interrupted CWE
        ordered_dict = {}

        # First add the interrupted CWE
        if current_cwe in vulnerability_dict:
            ordered_dict[current_cwe] = vulnerability_dict[current_cwe]

        # Then add the rest
        for cwe_id, vuln_type in vulnerability_dict.items():
            if cwe_id != current_cwe:
                ordered_dict[cwe_id] = vuln_type

        return self.generate_samples(ordered_dict, n_samples, resume=True)

    def get_pipeline_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the current pipeline state.
        
        Returns:
            Dictionary containing pipeline statistics
        """
        completed_samples = self.file_manager.get_completed_samples()
        context_stats = self.context_manager.get_context_statistics()

        # Group completed samples by CWE
        cwe_counts = {}
        for cwe_id, sample_num in completed_samples:
            cwe_counts[cwe_id] = cwe_counts.get(cwe_id, 0) + 1

        return {
            "total_completed_samples": len(completed_samples),
            "samples_by_cwe": cwe_counts,
            "context_statistics": context_stats,
            "pipeline_config": {
                "provider": self.model_config.provider,
                "model": self.model_config.model,
                "temperature": self.model_config.temperature,
                "output_directory": self.pipeline_config.output_dir,
                "max_contexts": self.pipeline_config.max_contexts
            }
        }
