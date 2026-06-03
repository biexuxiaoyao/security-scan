"""AI-assisted secondary classification module.

This module implements the "secondary classification" pattern (see 2.7):
rule engine findings are sent to an LLM for confirmation/dismissal,
reducing false positives beyond what static analysis can achieve.

Architecture
------------
PromptBuilder  →  AIProvider  →  BatchProcessor  →  AIClassifier
     |                |                |                 |
  builds          sends to         splits into      orchestrates
  structured      OpenAI /         batches,         the full
  prompts         Azure /          retries,         pipeline
                  Ollama           merges

Usage
-----
    classifier = AIClassifier(config)
    enriched_findings = classifier.classify(candidate_findings)
"""
