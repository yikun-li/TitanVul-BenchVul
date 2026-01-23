# Out of Distribution, Out of Luck: How Well Can LLMs Trained on Vulnerability Datasets Detect Top 25 CWE Weaknesses?

<p align="left">
    <a href="https://arxiv.org/abs/2507.21817"><img src="https://img.shields.io/badge/arXiv-comingsoon-b31b1b.svg?style=for-the-badge"></a>
    <a href="https://opensource.org/license/mit/"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge"></a>
</p>

<p align="left">
    📜 &nbsp;<a href="#-overview">Overview</a>
    | 📚&nbsp;<a href="#-datasets">Datasets</a>
    | 🏗️&nbsp;<a href="#-pipeline">Pipeline</a>
    | 📝&nbsp;<a href="#-citation">Citation</a>
</p>

- **(2025-12-17)** This paper was accepted for publication at ICSE 2026.
- **(2025-09-30)** We updated the most recent CVE descriptions in the TitanVul dataset.
- **(2025-08-11)** We updated the dataset to include more metadata.
- **(2025-07-31)** We released our paper and dataset for reproducibility.

## 📜 Overview

**BenchVul** and **TitanVul** are high-quality resources for evaluating and training machine learning models for
vulnerability detection:

* **BenchVul** is a comprehensive, manually verified benchmark for the Top 25 Most Dangerous CWEs.
* **TitanVul** is a large-scale, rigorously validated vulnerability dataset, built with multi-agent LLM verification and
  aggregation from public sources.
* The **RVG Framework** enables realistic vulnerability synthesis for underrepresented or rare CWE types.
* Our work exposes the limitations of current datasets, demonstrates the importance of benchmark-driven evaluation, and
  provides resources for reproducible research.

### Repository Structure

```
.
├── datasets/
│   ├── BenchVul.csv.zip             # Benchmark for Top 25 Most Dangerous CWEs
│   └── TitanVul.csv.zip             # High-quality training dataset
├── vulnerability_generation/        # RVG framework for synthetic data
├── vulnerability_fixing_detection/  # Multi-agent fix detection pipeline
└── README.md
```

## 📚 Datasets

### Dataset Access

The TitanVul and BenchVul datasets are hosted on Hugging Face for ease of access and reproducibility:

👉 **Hugging Face Datasets**: [TitanVul](https://huggingface.co/datasets/yikun-li/TitanVul) | [BenchVul](https://huggingface.co/datasets/yikun-li/BenchVul)

### BenchVul Benchmark

* **Balanced**: 50 vulnerable + 50 fixed samples per CWE
* **Coverage**: Refined Top 25 Most Dangerous CWEs, removing ambiguous/overlapping categories for clarity  ([See details](others/top25cwe.md))
* **Quality**: 92% correctness rate, verified by expert manual review
* **Purpose**: Reliable, independent evaluation of model generalization

### TitanVul Dataset

* **Scale**: 38,548 vulnerability-fix function pairs
* **Quality**: Constructed via a multi-agent LLM framework, combining seven public datasets, extensive deduplication,
  and rigorous validation
* **Purpose**: High-quality training data for developing generalizable models

## 🏗️ Pipeline

### Vulnerability Generation: RVG Framework

**Purpose**: Generate synthetic vulnerability samples using a multi-agent LLM system

**Key Features**:

- Four-agent collaboration system (Context & Threat Modeler, Vulnerable Implementer, Security Auditor, Security
  Reviewer)
- Realistic application contexts and attack vectors
- Support for multiple programming languages and CWE types

#### Usage
```bash
cd vulnerability_generation_pipeline

# Generate vulnerability samples
python main.py --provider openai --model gpt-4o

# Generate for specific CWEs
python main.py --specific-cwe CWE-89 CWE-22 --target-count 50
```

📖 [Detailed Documentation](vulnerability_generation/README.md)

### Vulnerability Fixing Detection Pipeline

**Purpose**: Detect whether code changes are attempts to fix security vulnerabilities

**Key Features**:

- Three-agent system (Auditor, Critic, Consensus) for comprehensive analysis
- Possibility scoring system (0-3 scale) for fix likelihood assessment

#### Usage

```bash
cd vulnerability_fixing_detection_pipeline

# Analyze vulnerability fixes
python main.py --input your_data.csv --provider openai --model gpt-4o

# With Anthropic Claude
python main.py --input your_data.csv --provider anthropic --model claude-3-sonnet-20240229
```

📖 [Detailed Documentation](vulnerability_fixing_detection/README.md)

## 📝 Citation

```bibtex
@article{li2025titanvul,
  title={Out of Distribution, Out of Luck: How Well Can LLMs Trained on Vulnerability Datasets Detect Top 25 CWE Weaknesses?},
  author={Li, Yikun and Bui, Ngoc Tan and Zhang, Ting and Weyssow, Martin and Yang, Chengran and Zhou, Xin and Jiang, Jinfeng and Chen, Junkai and Huang, Huihui and Nguyen, Huu Hung and Ho, Chiok Yew and Tan, Jie and Li, Ruiyin and Yin, Yide and Ang, Han Wei and Liauw, Frank and Ouh, Eng Lieh and Shar, Lwin Khin and Lo, David},
  journal={arXiv preprint arXiv:2507.21817},
  year={2025}
}
```
