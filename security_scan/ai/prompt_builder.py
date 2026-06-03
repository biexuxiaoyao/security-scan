"""Structured prompt builder for AI classifier."""

from __future__ import annotations

from typing import Any

_SYSTEM_PROMPT = """You are a code security analysis expert. Your task is to determine whether a code snippet contains a genuine security issue (plaintext password, hardcoded secret, API key, token, etc.) or a false positive.

Respond ONLY with a JSON object in this exact format:
{"is_sensitive": true/false, "confidence": 0.0-1.0, "reason": "brief explanation"}

Rules:
- If the value is a boolean (true/false), number, enum, version string, or URL → false positive
- If the value is a log template placeholder like {} → false positive
- If the value is test/mock data in a test file → false positive
- If the value is a genuine password, API key, token, or connection string → is_sensitive: true
- If the value starts with an encryption marker (BEE_, ENC(, {cipher}) → already encrypted, is_sensitive: false
"""


class PromptBuilder:
    """Builds structured classification prompts with code context and judgement rules.

    Follows the design in 2.7.4 of the requirements analysis.
    """

    MAX_CONTEXT_LINES = 10  # 5 before + 5 after

    def build(self, finding: dict, source_lines: list[str] | None = None) -> list[dict[str, str]]:
        """Construct a chat-style message list for the LLM.

        Parameters
        ----------
        finding :
            A single candidate finding from the rule engine.
        source_lines :
            Full source file split into lines. If provided, context
            lines around the finding are included.

        Returns
        -------
        list[dict[str, str]]
            Messages list with ``role`` and ``content`` keys,
            ready to pass to OpenAI / Azure / Ollama API.
        """
        file_path = finding.get("file_path", "?")
        line_number = finding.get("line_number", 0)
        matched = finding.get("matched_content", "")
        rule_id = finding.get("rule_id", "?")
        description = finding.get("description", "")

        # Build context block
        context_block = ""
        if source_lines and line_number:
            context_block = self._build_context(source_lines, line_number)

        user_content = (
            f"File: {file_path}\n"
            f"Line: {line_number}\n"
            f"Rule triggered: {rule_id} — {description}\n"
            f"Matched content: {matched!r}\n"
        )
        if context_block:
            user_content += f"\nCode context:\n```\n{context_block}```\n"
        user_content += "\nIs this a real security issue or a false positive?"

        return [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ]

    def build_batch(
        self,
        findings: list[dict],
        source_lines_map: dict[str, list[str]] | None = None,
    ) -> list[list[dict[str, str]]]:
        """Build prompts for multiple findings in batch.

        Each finding produces its own prompt (independent classification).
        """
        prompts: list[list[dict[str, str]]] = []
        for f in findings:
            lines = None
            fp = f.get("file_path")
            if source_lines_map and fp:
                lines = source_lines_map.get(fp)
            prompts.append(self.build(f, lines))
        return prompts

    def parse_response(self, response_text: str) -> dict[str, bool | float | str]:
        """Parse the LLM's JSON response into a structured verdict.

        Parameters
        ----------
        response_text :
            Raw response text from the LLM.

        Returns
        -------
        dict
            With keys: ``is_sensitive`` (bool), ``confidence`` (float),
            ``reason`` (str). Defaults to ``{"is_sensitive": True, "confidence": 0.5, "reason": "parse error"}``
            on failure.
        """
        import json
        import re

        # Try to extract JSON from the response (handles markdown code fences)
        json_match = re.search(r"\{[^}]+\}", response_text, re.DOTALL)
        if json_match:
            try:
                result = json.loads(json_match.group(0))
                return {
                    "is_sensitive": bool(result.get("is_sensitive", True)),
                    "confidence": min(max(float(result.get("confidence", 0.5)), 0.0), 1.0),
                    "reason": str(result.get("reason", "")),
                }
            except (json.JSONDecodeError, ValueError, TypeError):
                pass

        # Fallback
        return {"is_sensitive": True, "confidence": 0.5, "reason": "AI response parse error"}

    # ── internal ──────────────────────────────────────────────

    @staticmethod
    def _build_context(source_lines: list[str], target_line: int, radius: int = 5) -> str:
        """Extract context lines around the target line."""
        if not source_lines:
            return ""
        idx = target_line - 1  # 0-based
        start = max(0, idx - radius)
        end = min(len(source_lines), idx + radius + 1)
        lines = []
        for i in range(start, end):
            prefix = ">>>" if i == idx else "   "
            lines.append(f"{prefix} {i + 1:>5}: {source_lines[i].rstrip()}")
        return "\n".join(lines)
