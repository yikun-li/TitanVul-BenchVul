#!/usr/bin/env python3
"""
Main entry point for the Vulnerability Pipeline.

This script provides a command-line interface for running the vulnerability
generation pipeline with various configuration options.
"""

import argparse
import sys
import os

from config.settings import load_config, VulnerabilityTypes
from pipeline import VulnerabilityPipeline
from utils.logging_utils import setup_logger

# Set up main logger
logger = setup_logger(__name__)


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser."""
    parser = argparse.ArgumentParser(
        description="Generate synthetic vulnerability samples for security research",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage with OpenAI
  python main.py --provider openai --model gpt-4o

  # Use Anthropic Claude
  python main.py --provider anthropic --model claude-3-sonnet-20240229

  # Generate specific number of samples
  python main.py --target-count 100 --multiplier 2

  # Use specific languages
  python main.py --languages Python Java JavaScript

  # Custom output directory
  python main.py --output-dir results --target-count 50
        """
    )

    # Model configuration
    parser.add_argument(
        "--provider",
        choices=["openai", "anthropic"],
        default="openai",
        help="Model provider to use (default: openai)"
    )

    parser.add_argument(
        "--model",
        default="gpt-4o",
        help="Model name to use (default: gpt-4o)"
    )

    parser.add_argument(
        "--temperature",
        type=float,
        default=0.7,
        help="Temperature for text generation (default: 0.7)"
    )

    # Pipeline configuration
    parser.add_argument(
        "--output-dir",
        default="_output",
        help="Directory for output files (default: _output)"
    )

    parser.add_argument(
        "--target-count",
        type=int,
        default=60,
        help="Target number of samples per vulnerability type (default: 60)"
    )

    parser.add_argument(
        "--multiplier",
        type=int,
        default=1,
        help="Multiplier for additional security samples (default: 1)"
    )

    parser.add_argument(
        "--max-contexts",
        type=int,
        default=30,
        help="Maximum number of contexts to maintain (default: 30)"
    )

    parser.add_argument(
        "--languages",
        nargs="+",
        help="Programming languages to use (default: Java Python C JavaScript C# C++ PHP Ruby)"
    )

    # Execution options
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="Don't resume from previous runs"
    )

    parser.add_argument(
        "--list-vulnerabilities",
        action="store_true",
        help="List all available vulnerability types and exit"
    )

    parser.add_argument(
        "--specific-cwe",
        nargs="+",
        help="Generate samples for specific CWE IDs only"
    )

    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show pipeline statistics and exit"
    )

    # Logging options
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )

    parser.add_argument(
        "--log-file",
        help="Log file path (default: vulnerability_generation.log)"
    )

    return parser


def list_vulnerabilities() -> None:
    """List all available vulnerability types."""
    print("Available Vulnerability Types:")
    print("=" * 50)

    for cwe_id, description in VulnerabilityTypes.VULNERABILITY_DICT.items():
        print(f"{cwe_id}: {description}")
        if ":" in description:
            # Show subtypes if available
            main_type, subtypes = description.split(":", 1)
            subtype_list = [s.strip() for s in subtypes.split("/")]
            for subtype in subtype_list[:3]:  # Show first 3 subtypes
                print(f"  - {subtype}")
            if len(subtype_list) > 3:
                print(f"  ... and {len(subtype_list) - 3} more")
        print()


def validate_environment() -> bool:
    """Validate that required environment variables are set."""
    required_vars = []

    # Check if any API key is available
    if not os.getenv("OPENAI_API_KEY") and not os.getenv("ANTHROPIC_API_KEY"):
        required_vars.append("OPENAI_API_KEY or ANTHROPIC_API_KEY")

    if required_vars:
        logger.error("Missing required environment variables:")
        for var in required_vars:
            logger.error(f"  - {var}")
        return False

    return True


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # Handle special commands
    if args.list_vulnerabilities:
        list_vulnerabilities()
        return 0

    # Validate environment
    if not validate_environment():
        return 1

    # Configure logging
    import logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = setup_logger(
        __name__,
        level=log_level,
        log_file=args.log_file,
        console_output=True
    )

    try:
        # Load configuration
        model_config, pipeline_config, api_credentials = load_config(
            provider=args.provider,
            model=args.model,
            temperature=args.temperature,
            output_dir=args.output_dir,
            max_contexts=args.max_contexts,
            target_count=args.target_count,
            multiplier=args.multiplier,
            languages=args.languages
        )

        # Initialize pipeline
        pipeline = VulnerabilityPipeline(
            model_config=model_config,
            pipeline_config=pipeline_config,
            api_credentials=api_credentials
        )

        # Handle stats command
        if args.stats:
            stats = pipeline.get_pipeline_statistics()
            print("\nPipeline Statistics:")
            print("=" * 50)
            print(f"Total completed samples: {stats['total_completed_samples']}")
            print(f"Output directory: {stats['pipeline_config']['output_directory']}")
            print(f"Model provider: {stats['pipeline_config']['provider']}")
            print(f"Model: {stats['pipeline_config']['model']}")
            print(f"Max contexts: {stats['pipeline_config']['max_contexts']}")

            if stats['samples_by_cwe']:
                print("\nSamples by CWE:")
                for cwe_id, count in sorted(stats['samples_by_cwe'].items()):
                    print(f"  {cwe_id}: {count} samples")

            return 0

        # Prepare vulnerability dictionary
        vulnerability_dict = VulnerabilityTypes.VULNERABILITY_DICT

        # Filter for specific CWEs if requested
        if args.specific_cwe:
            vulnerability_dict = {
                cwe_id: description
                for cwe_id, description in vulnerability_dict.items()
                if cwe_id in args.specific_cwe
            }

            if not vulnerability_dict:
                logger.error("No valid CWE IDs found in the specified list")
                return 1

            logger.info(f"Generating samples for specific CWEs: {list(vulnerability_dict.keys())}")

        # Validate API connection
        if not pipeline.api_client.validate_connection():
            logger.error("Failed to validate API connection")
            return 1

        # Run the pipeline
        logger.info("Starting vulnerability generation pipeline...")

        # Get current sample counts
        completed_samples = pipeline.file_manager.get_completed_samples()
        current_counts = {}
        for cwe_id in vulnerability_dict.keys():
            cwe_samples = [(cwe, sample_num) for cwe, sample_num in completed_samples if cwe == cwe_id]
            current_counts[cwe_id] = len(cwe_samples)

        # Generate samples
        results = pipeline.generate_needed_samples(
            vulnerability_dict=vulnerability_dict,
            target_count=args.target_count,
            current_counts=current_counts,
            multiplier=args.multiplier,
            resume=not args.no_resume
        )

        # Save combined results
        if results:
            combined_path = pipeline.file_manager.save_combined_results(results)
            logger.info(f"All results saved to: {combined_path}")

        # Display final statistics
        final_stats = pipeline.get_pipeline_statistics()
        logger.info(f"Pipeline completed. Total samples generated: {final_stats['total_completed_samples']}")

        return 0

    except KeyboardInterrupt:
        logger.info("Pipeline interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Pipeline failed with error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
