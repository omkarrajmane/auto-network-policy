"""
LLM Provider abstraction for AutoNetworkPolicy.

This module provides an abstract base class for LLM providers and a concrete
implementation for OpenRouter API integration.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import json
import os
import re
import shutil
import subprocess
import time

import requests
import yaml


@dataclass
class LLMConfig:
    """Configuration for LLM provider."""

    provider: str = "openrouter"
    model: str = "google/gemini-2.5-flash"
    api_key: str = ""
    base_url: str = ""
    max_tokens: int = 1024
    temperature: float = 0.7
    timeout_seconds: int = 30

    @classmethod
    def from_dict(cls, config_dict: dict[str, Any]) -> "LLMConfig":
        """Create config from dictionary."""
        provider = config_dict.get("provider", "openrouter")
        if provider == "claude_subprocess":
            default_model = "claude-opus-4-6"
            default_timeout = 120
        elif provider == "opencode_subprocess":
            default_model = "openai/gpt-5.3-codex"
            default_timeout = 120
        else:
            default_model = "google/gemini-2.5-flash"
            default_timeout = 30

        return cls(
            provider=provider,
            model=config_dict.get("model", default_model),
            api_key=config_dict.get("api_key", ""),
            base_url=config_dict.get("base_url", ""),
            max_tokens=config_dict.get("max_tokens", 1024),
            temperature=config_dict.get("temperature", 0.7),
            timeout_seconds=config_dict.get("timeout_seconds", default_timeout),
        )

    @classmethod
    def from_yaml(cls, yaml_path: str | Path) -> "LLMConfig":
        """Load configuration from YAML file."""
        path = Path(yaml_path)
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {yaml_path}")

        with open(path) as f:
            config = yaml.safe_load(f)

        if "llm" not in config:
            raise ValueError("Config file missing 'llm' section")

        llm_config = config["llm"].copy()

        # Handle environment variable substitution for API key
        api_key = llm_config.get("api_key", "")
        if api_key.startswith("${") and api_key.endswith("}"):
            env_var = api_key[2:-1]
            api_key = os.environ.get(env_var, "")
            if not api_key:
                raise ValueError(f"Environment variable {env_var} not set")

        llm_config["api_key"] = api_key

        return cls.from_dict(llm_config)


class LLMProvider(ABC):
    """Abstract base class for LLM providers.

    Subclasses must implement:
    - generate(): Generate mutation DSL from context
    - validate_config(): Validate provider configuration
    """

    def __init__(self, config: LLMConfig | None = None):
        """Initialize provider with optional configuration.

        Args:
            config: LLM configuration. If None, loads from config.yaml.
        """
        if config is None:
            # Try to load from default config.yaml location
            config_path = Path(__file__).parent.parent / "config.yaml"
            config = LLMConfig.from_yaml(config_path)

        self.config = config
        self._validate_and_setup()

    def _validate_and_setup(self) -> None:
        """Internal validation and setup."""
        if not self.validate_config():
            raise ValueError("Invalid provider configuration")

    @abstractmethod
    def generate(self, context: dict[str, Any]) -> dict[str, Any]:
        """Generate mutation DSL JSON from context.

        Args:
            context: Dictionary containing:
                - current_policy: List of current firewall rules
                - recent_mutations: History of recent mutations
                - performance_metrics: Throughput, hit rates, etc.
                - iteration: Current iteration number
                - max_iterations: Maximum iterations allowed

        Returns:
            Dictionary with mutation details:
                - mutation_type: Type of mutation (e.g., "swap", "merge")
                - description: Human-readable description
                - operation: Structured operation details
        """
        pass

    @abstractmethod
    def validate_config(self) -> bool:
        """Validate provider configuration.

        Returns:
            True if configuration is valid, False otherwise.
        """
        pass


class OpenRouterProvider(LLMProvider):
    """OpenRouter API provider implementation.

    Uses OpenRouter's unified API to access multiple LLM models,
    specifically configured for Gemini Flash 2.5.
    """

    API_URL = "https://openrouter.ai/api/v1/chat/completions"

    SYSTEM_PROMPT = """You are a firewall optimization expert specializing in nftables rulesets.

Your task is to analyze firewall policy data and propose a SINGLE mutation that improves
performance while maintaining exact security equivalence.

=== MUTATION DSL ===

You must respond with a JSON object containing one of these mutation types:

1. SWAP(i, j) - Swap two rules
   {"mutation_type": "swap", "description": "Swap rules 5 and 12 to put high-hit rule earlier", "operation": {"name": "swap", "args": [5, 12]}}

2. MOVE_BEFORE(i, j) - Move rule i to before rule j
   {"mutation_type": "move_before", "description": "Move rule 8 before rule 3", "operation": {"name": "move_before", "args": [8, 3]}}

3. MERGE_ADJACENT(i) - Merge rule i with rule i+1 if they have same action and compatible IPs
   {"mutation_type": "merge_adjacent", "description": "Merge rules 10 and 11 (both accept from same subnet)", "operation": {"name": "merge_adjacent", "args": [10]}}

4. REMOVE_SHADOWED(i) - Remove rule i if fully shadowed by earlier rules
   {"mutation_type": "remove_shadowed", "description": "Remove rule 15, shadowed by rule 7", "operation": {"name": "remove_shadowed", "args": [15]}}

5. CONSOLIDATE(i, j, ...) - Merge 2+ adjacent rules with same action and complementary CIDRs
   {"mutation_type": "consolidate", "description": "Consolidate rules 5-7 into a single rule", "operation": {"name": "consolidate", "args": [5, 6, 7]}}
   Requirements: All rules must have same action, same dst_ip, same protocol; src_ips must form a collapsible CIDR range

6. SPLIT(i, replacements) - Split one rule into more specific subnet rules
   {"mutation_type": "split", "description": "Split rule 10 into specific department subnets", "operation": {"name": "split", "args": [10], "replacements": [{"src_ip": "10.0.1.0/24", "dst_ip": "192.168.1.0/24", "action": "accept"}, {"src_ip": "10.0.2.0/24", "dst_ip": "192.168.1.0/24", "action": "accept"}]}}
   Requirements: All replacements must be subsets of original src_ip and dst_ip; max 5 replacements

=== CONSTRAINTS (IP-ONLY MODE v1) ===

- Rules are 0-indexed
- Index 0 ("ct state established,related accept") is FIXED - never move it
- Last rule (default-drop) is FIXED - never move it
- Only IP-level mutations allowed in v1 (no port/protocol changes)
- Mutations must preserve exact IP reachability equivalence
- Return ONLY the JSON object, no markdown formatting

=== DECISION GUIDANCE ===

Consider these factors when proposing mutations:
- Rules with high hit counts should typically be moved earlier
- Rules with 0 hits may be candidates for removal
- Adjacent rules with same action and overlapping IP ranges may be mergeable
- Look for rules that are logically similar but separated by unrelated rules

Propose the single most impactful mutation based on the context below."""

    def validate_config(self) -> bool:
        """Validate OpenRouter configuration.

        Returns:
            True if API key is present and config is valid.
        """
        if not self.config.api_key:
            return False
        if not self.config.model:
            return False
        if self.config.temperature < 0 or self.config.temperature > 2:
            return False
        if self.config.max_tokens < 1:
            return False
        return True

    def _build_prompt(self, context: dict[str, Any]) -> str:
        """Build the prompt from context.

        Args:
            context: Context dictionary with policy, metrics, etc.

        Returns:
            Formatted prompt string.
        """
        lines = []

        # Add current policy info
        current_policy = context.get("current_policy", [])
        lines.append(f"CURRENT POLICY ({len(current_policy)} rules):")
        for i, rule in enumerate(current_policy):
            lines.append(f"  [{i}] {rule}")

        # Add performance metrics
        metrics = context.get("performance_metrics", {})
        if metrics:
            lines.append("\nPERFORMANCE METRICS:")
            for key, value in metrics.items():
                lines.append(f"  {key}: {value}")

        # Add counter/hit rate data if available
        if "hit_rates" in metrics:
            lines.append("\nRULE HIT RATES:")
            for rule_idx, hits in metrics["hit_rates"].items():
                lines.append(f"  Rule {rule_idx}: {hits} hits")

        # Add recent mutation history
        recent_mutations = context.get("recent_mutations", [])
        if recent_mutations:
            lines.append(f"\nRECENT MUTATIONS (last {len(recent_mutations)}):")
            for i, mut in enumerate(recent_mutations[-5:], 1):
                mut_type = mut.get("mutation_type", "unknown")
                desc = mut.get("description", "no description")
                score_change = mut.get("score_change", "N/A")
                lines.append(f"  {i}. {mut_type}: {desc} (score change: {score_change})")

        # Add iteration info
        iteration = context.get("iteration", 0)
        max_iterations = context.get("max_iterations", 100)
        lines.append(f"\nITERATION: {iteration}/{max_iterations}")

        lines.append("\nBased on this data, propose the SINGLE most impactful mutation.")
        lines.append("Return ONLY the JSON response, no markdown formatting.")

        return "\n".join(lines)

    def _parse_response(self, response_text: str) -> dict[str, Any]:
        """Parse and validate LLM response.

        Args:
            response_text: Raw text response from LLM.

        Returns:
            Parsed and validated mutation dictionary.

        Raises:
            ValueError: If response cannot be parsed or is invalid.
        """
        # Clean up potential markdown formatting
        text = response_text.strip()

        # Remove markdown code blocks if present
        if text.startswith("```json"):
            text = text[7:]
        if text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]

        text = text.strip()

        # Try to extract JSON if embedded in other text
        json_match = re.search(r"\{.*\}", text, re.DOTALL)
        if json_match:
            text = json_match.group(0)

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse JSON response: {e}") from e

        # Validate required fields
        required_fields = ["mutation_type", "description", "operation"]
        for field in required_fields:
            if field not in parsed:
                raise ValueError(f"Missing required field: {field}")

        # Validate mutation type
        valid_types = {
            "swap",
            "move_before",
            "merge_adjacent",
            "remove_shadowed",
            "consolidate",
            "split",
        }
        if parsed["mutation_type"] not in valid_types:
            raise ValueError(
                f"Invalid mutation_type: {parsed['mutation_type']}. Must be one of: {valid_types}"
            )

        # Validate operation structure
        operation = parsed["operation"]
        if not isinstance(operation, dict):
            raise ValueError("operation must be a dictionary")
        if "name" not in operation:
            raise ValueError("operation must have a 'name' field")
        if "args" not in operation:
            raise ValueError("operation must have an 'args' field")
        if not isinstance(operation["args"], list):
            raise ValueError("operation.args must be a list")

        return parsed

    def _extract_mutation_from_reasoning(self, reasoning_text: str) -> dict[str, Any] | None:
        text = reasoning_text.strip()
        if not text:
            return None

        shadow_match = re.search(
            r"rule\s+(\d+)\s+is\s+shadowed(?:\s+by\s+rule\s+(\d+))?",
            text,
            re.IGNORECASE,
        )
        if shadow_match:
            idx = int(shadow_match.group(1))
            by_idx = shadow_match.group(2)
            description = f"Remove shadowed rule {idx}"
            if by_idx is not None:
                description += f", shadowed by rule {int(by_idx)}"
            return {
                "mutation_type": "remove_shadowed",
                "description": description,
                "operation": {"name": "remove_shadowed", "args": [idx]},
            }

        move_match = re.search(
            r"move\s+rule\s+(\d+)\s+before\s+rule\s+(\d+)",
            text,
            re.IGNORECASE,
        )
        if move_match:
            src = int(move_match.group(1))
            dst = int(move_match.group(2))
            return {
                "mutation_type": "move_before",
                "description": f"Move rule {src} before rule {dst}",
                "operation": {"name": "move_before", "args": [src, dst]},
            }

        swap_match = re.search(
            r"swap\s+rules?\s+(\d+)\s+(?:and|with)\s+(\d+)",
            text,
            re.IGNORECASE,
        )
        if swap_match:
            left = int(swap_match.group(1))
            right = int(swap_match.group(2))
            return {
                "mutation_type": "swap",
                "description": f"Swap rules {left} and {right}",
                "operation": {"name": "swap", "args": [left, right]},
            }

        return None

    def generate(self, context: dict[str, Any]) -> dict[str, Any]:
        """Generate mutation using OpenRouter API.

        Args:
            context: Dictionary with policy, metrics, history.

        Returns:
            Parsed mutation dictionary with type, description, and operation.

        Raises:
            requests.RequestException: On API errors.
            ValueError: On parsing or validation errors.
            TimeoutError: If request times out.
        """
        prompt = self._build_prompt(context)

        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://autonetworkpolicy.local",
            "X-Title": "AutoNetworkPolicy",
        }

        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }

        t0 = time.time()

        api_url = self.config.base_url.strip() or self.API_URL
        last_exc: Exception = RuntimeError("no attempts made")
        for attempt in range(3):
            if attempt > 0:
                time.sleep(5 * attempt)
            try:
                response = requests.post(
                    api_url,
                    headers=headers,
                    json=payload,
                    timeout=self.config.timeout_seconds,
                )
                response.raise_for_status()
                break
            except requests.Timeout:
                last_exc = TimeoutError(
                    f"OpenRouter API request timed out after {self.config.timeout_seconds}s"
                )
                continue
            except requests.ConnectionError as e:
                last_exc = e
                continue
            except requests.HTTPError as e:
                status_code = e.response.status_code if e.response else 0
                if status_code == 401:
                    raise ValueError("Authentication failed: Invalid API key") from e
                elif status_code == 0 or status_code >= 500:
                    last_exc = ValueError(f"OpenRouter server error: {status_code}")
                    continue
                elif status_code == 429:
                    time.sleep(10)
                    last_exc = e
                    continue
                else:
                    raise ValueError(f"API error: {status_code}") from e
        else:
            raise last_exc

        elapsed = time.time() - t0

        # Parse API response
        try:
            api_response = response.json()
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in API response: {e}") from e

        # Extract content from response
        if "choices" not in api_response or not api_response["choices"]:
            raise ValueError("No choices in API response")

        message = api_response["choices"][0].get("message", {})
        content = message.get("content", "")
        if content:
            mutation = self._parse_response(content)
        else:
            reasoning = message.get("reasoning", "")
            mutation = self._extract_mutation_from_reasoning(reasoning)
            if mutation is None:
                raise ValueError("Empty content in API response")

        # Add metadata
        mutation["_metadata"] = {
            "provider": "openrouter",
            "model": self.config.model,
            "latency_seconds": round(elapsed, 3),
            "input_tokens": api_response.get("usage", {}).get("prompt_tokens", 0),
            "output_tokens": api_response.get("usage", {}).get("completion_tokens", 0),
        }

        return mutation


class ClaudeSubprocessProvider(LLMProvider):
    SYSTEM_PROMPT = OpenRouterProvider.SYSTEM_PROMPT

    def validate_config(self) -> bool:
        if shutil.which("claude") is None:
            return False
        if not self.config.model:
            return False
        if self.config.temperature < 0 or self.config.temperature > 2:
            return False
        if self.config.max_tokens < 1:
            return False
        if self.config.timeout_seconds < 1:
            return False
        return True

    def _build_prompt(self, context: dict[str, Any]) -> str:
        """Build the prompt from context.

        Args:
            context: Context dictionary with policy, metrics, etc.

        Returns:
            Formatted prompt string.
        """
        lines = []

        # Add current policy info
        current_policy = context.get("current_policy", [])
        lines.append(f"CURRENT POLICY ({len(current_policy)} rules):")
        for i, rule in enumerate(current_policy):
            lines.append(f"  [{i}] {rule}")

        # Add performance metrics
        metrics = context.get("performance_metrics", {})
        if metrics:
            lines.append("\nPERFORMANCE METRICS:")
            for key, value in metrics.items():
                lines.append(f"  {key}: {value}")

        # Add counter/hit rate data if available
        if "hit_rates" in metrics:
            lines.append("\nRULE HIT RATES:")
            for rule_idx, hits in metrics["hit_rates"].items():
                lines.append(f"  Rule {rule_idx}: {hits} hits")

        # Add recent mutation history
        recent_mutations = context.get("recent_mutations", [])
        if recent_mutations:
            lines.append(f"\nRECENT MUTATIONS (last {len(recent_mutations)}):")
            for i, mut in enumerate(recent_mutations[-5:], 1):
                mut_type = mut.get("mutation_type", "unknown")
                desc = mut.get("description", "no description")
                score_change = mut.get("score_change", "N/A")
                lines.append(f"  {i}. {mut_type}: {desc} (score change: {score_change})")

        # Add iteration info
        iteration = context.get("iteration", 0)
        max_iterations = context.get("max_iterations", 100)
        lines.append(f"\nITERATION: {iteration}/{max_iterations}")

        lines.append("\nBased on this data, propose the SINGLE most impactful mutation.")
        lines.append("Return ONLY the JSON response, no markdown formatting.")

        return "\n".join(lines)

    def _parse_response(self, response_text: str) -> dict[str, Any]:
        """Parse and validate LLM response.

        Args:
            response_text: Raw text response from LLM.

        Returns:
            Parsed and validated mutation dictionary.

        Raises:
            ValueError: If response cannot be parsed or is invalid.
        """
        # Clean up potential markdown formatting
        text = response_text.strip()

        # Remove markdown code blocks if present
        if text.startswith("```json"):
            text = text[7:]
        if text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]

        text = text.strip()

        # Try to extract JSON if embedded in other text
        json_match = re.search(r"\{.*\}", text, re.DOTALL)
        if json_match:
            text = json_match.group(0)

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse JSON response: {e}") from e

        # Validate required fields
        required_fields = ["mutation_type", "description", "operation"]
        for field in required_fields:
            if field not in parsed:
                raise ValueError(f"Missing required field: {field}")

        # Validate mutation type
        valid_types = {
            "swap",
            "move_before",
            "merge_adjacent",
            "remove_shadowed",
            "consolidate",
            "split",
        }
        if parsed["mutation_type"] not in valid_types:
            raise ValueError(
                f"Invalid mutation_type: {parsed['mutation_type']}. Must be one of: {valid_types}"
            )

        # Validate operation structure
        operation = parsed["operation"]
        if not isinstance(operation, dict):
            raise ValueError("operation must be a dictionary")
        if "name" not in operation:
            raise ValueError("operation must have a 'name' field")
        if "args" not in operation:
            raise ValueError("operation must have an 'args' field")
        if not isinstance(operation["args"], list):
            raise ValueError("operation.args must be a list")

        return parsed

    def generate(self, context: dict[str, Any]) -> dict[str, Any]:
        prompt = self._build_prompt(context)

        command = [
            "claude",
            "-p",
            prompt,
            "--model",
            self.config.model,
            "--output-format",
            "json",
            "--system-prompt",
            self.SYSTEM_PROMPT,
            "--disallowed-tools",
            "Bash,Read,Write,Edit,Glob,Grep,WebSearch,WebFetch",
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(
                f"Claude subprocess timed out after {self.config.timeout_seconds}s"
            ) from exc

        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            stdout = (result.stdout or "").strip()
            details = stderr if stderr else stdout
            raise ValueError(f"Claude CLI failed with exit code {result.returncode}: {details}")

        raw_output = (result.stdout or "").strip()
        if not raw_output:
            raise ValueError("Claude CLI returned empty output")

        try:
            cli_response = json.loads(raw_output)
        except json.JSONDecodeError:
            json_match = re.search(r"\{.*\}", raw_output, re.DOTALL)
            if not json_match:
                raise ValueError("Failed to parse Claude CLI JSON output")
            try:
                cli_response = json.loads(json_match.group(0))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Failed to parse Claude CLI JSON output: {exc}") from exc

        if cli_response.get("is_error") is True:
            error_message = (
                cli_response.get("result") or cli_response.get("error") or "unknown error"
            )
            raise ValueError(f"Claude CLI response indicates error: {error_message}")

        response_text = cli_response.get("result", "")
        if not response_text:
            raise ValueError("Claude CLI response missing 'result' content")

        mutation = self._parse_response(response_text)

        usage = cli_response.get("usage", {}) or {}
        duration_api_ms = cli_response.get("duration_api_ms", cli_response.get("duration_ms", 0))
        try:
            latency_seconds = round(float(duration_api_ms) / 1000.0, 3)
        except (TypeError, ValueError):
            latency_seconds = 0.0

        mutation["_metadata"] = {
            "provider": "claude_subprocess",
            "model": self.config.model,
            "latency_seconds": latency_seconds,
            "input_tokens": usage.get("input_tokens", 0),
            "output_tokens": usage.get("output_tokens", 0),
        }

        return mutation


class OpenCodeSubprocessProvider(LLMProvider):
    SYSTEM_PROMPT = OpenRouterProvider.SYSTEM_PROMPT

    def validate_config(self) -> bool:
        if shutil.which("opencode") is None:
            return False
        if not self.config.model:
            return False
        if self.config.temperature < 0 or self.config.temperature > 2:
            return False
        if self.config.max_tokens < 1:
            return False
        if self.config.timeout_seconds < 1:
            return False
        return True

    def _build_prompt(self, context: dict[str, Any]) -> str:
        lines = []

        current_policy = context.get("current_policy", [])
        lines.append(f"CURRENT POLICY ({len(current_policy)} rules):")
        for i, rule in enumerate(current_policy):
            lines.append(f"  [{i}] {rule}")

        metrics = context.get("performance_metrics", {})
        if metrics:
            lines.append("\nPERFORMANCE METRICS:")
            for key, value in metrics.items():
                lines.append(f"  {key}: {value}")

        recent_mutations = context.get("recent_mutations", [])
        if recent_mutations:
            lines.append(f"\nRECENT MUTATIONS (last {len(recent_mutations)}):")
            for i, mut in enumerate(recent_mutations[-5:], 1):
                mut_type = mut.get("mutation_type", "unknown")
                desc = mut.get("description", "no description")
                score_change = mut.get("score_change", "N/A")
                lines.append(f"  {i}. {mut_type}: {desc} (score change: {score_change})")

        traffic_profile = context.get("traffic_profile")
        if traffic_profile:
            lines.append("\nTRAFFIC PROFILE:")
            lines.append(f"  name: {traffic_profile.get('name', 'unknown')}")
            for flow in traffic_profile.get("flow_classes", [])[:10]:
                lines.append(
                    f"  - {flow.get('name')} | weight={flow.get('weight')} "
                    f"proto={flow.get('protocol')} dport={flow.get('dst_port')}"
                )
            guidance = traffic_profile.get("guidance")
            if guidance:
                lines.append(f"  guidance: {guidance}")

        iteration = context.get("iteration", 0)
        max_iterations = context.get("max_iterations", 100)
        lines.append(f"\nITERATION: {iteration}/{max_iterations}")

        lines.append("\nBased on this data, propose the SINGLE most impactful mutation.")
        lines.append("Return ONLY the JSON response, no markdown formatting.")

        return "\n".join(lines)

    def _parse_response(self, response_text: str) -> dict[str, Any]:
        text = response_text.strip()

        if text.startswith("```json"):
            text = text[7:]
        if text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

        json_match = re.search(r"\{.*\}", text, re.DOTALL)
        if json_match:
            text = json_match.group(0)

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"Failed to parse JSON response: {e}") from e

        required_fields = ["mutation_type", "description", "operation"]
        for field in required_fields:
            if field not in parsed:
                raise ValueError(f"Missing required field: {field}")

        valid_types = {
            "swap",
            "move_before",
            "merge_adjacent",
            "remove_shadowed",
            "consolidate",
            "split",
        }
        if parsed["mutation_type"] not in valid_types:
            raise ValueError(
                f"Invalid mutation_type: {parsed['mutation_type']}. Must be one of: {valid_types}"
            )

        operation = parsed["operation"]
        if not isinstance(operation, dict):
            raise ValueError("operation must be a dictionary")
        if "name" not in operation:
            raise ValueError("operation must have a 'name' field")
        if "args" not in operation:
            raise ValueError("operation must have an 'args' field")
        if not isinstance(operation["args"], list):
            raise ValueError("operation.args must be a list")

        return parsed

    def generate(self, context: dict[str, Any]) -> dict[str, Any]:
        prompt = self._build_prompt(context)
        full_prompt = (
            f"{self.SYSTEM_PROMPT}\n\n"
            f"{prompt}\n\n"
            "IMPORTANT: Return ONLY one JSON object with keys mutation_type, description, operation."
        )

        command = [
            "opencode",
            "run",
            full_prompt,
            "-m",
            self.config.model,
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(
                f"OpenCode subprocess timed out after {self.config.timeout_seconds}s"
            ) from exc

        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            stdout = (result.stdout or "").strip()
            details = stderr if stderr else stdout
            raise ValueError(f"OpenCode CLI failed with exit code {result.returncode}: {details}")

        raw_output = (result.stdout or "").strip()
        if not raw_output:
            raise ValueError("OpenCode CLI returned empty output")

        mutation = self._parse_response(raw_output)
        mutation["_metadata"] = {
            "provider": "opencode_subprocess",
            "model": self.config.model,
            "latency_seconds": 0.0,
            "input_tokens": 0,
            "output_tokens": 0,
        }
        return mutation


class LLMProviderFactory:
    """Factory for creating LLM provider instances."""

    _providers: dict[str, type[LLMProvider]] = {
        "openrouter": OpenRouterProvider,
        "claude_subprocess": ClaudeSubprocessProvider,
        "opencode_subprocess": OpenCodeSubprocessProvider,
    }

    @classmethod
    def create(
        cls, provider_name: str | None = None, config: LLMConfig | None = None
    ) -> LLMProvider:
        """Create an LLM provider instance.

        Args:
            provider_name: Name of the provider (e.g., "openrouter").
                          If None, reads from config.
            config: Optional configuration object.

        Returns:
            Configured LLMProvider instance.

        Raises:
            ValueError: If provider name is unknown.
        """
        if config is None:
            # Load from default config
            config_path = Path(__file__).parent.parent / "config.yaml"
            config = LLMConfig.from_yaml(config_path)

        if provider_name is None:
            provider_name = config.provider

        provider_class = cls._providers.get(provider_name.lower())
        if provider_class is None:
            available = ", ".join(cls._providers.keys())
            raise ValueError(f"Unknown provider: {provider_name}. Available providers: {available}")

        return provider_class(config)

    @classmethod
    def register(cls, name: str, provider_class: type[LLMProvider]) -> None:
        """Register a new provider class.

        Args:
            name: Provider identifier.
            provider_class: Class implementing LLMProvider.
        """
        cls._providers[name.lower()] = provider_class

    @classmethod
    def list_providers(cls) -> list[str]:
        """List available provider names."""
        return list(cls._providers.keys())


def create_context(
    current_policy: list[dict[str, Any]],
    recent_mutations: list[dict[str, Any]],
    performance_metrics: dict[str, Any],
    iteration: int,
    max_iterations: int,
) -> dict[str, Any]:
    """Create a properly formatted context dictionary for LLM generation.

    Args:
        current_policy: List of current firewall rules.
        recent_mutations: History of recent mutations with their outcomes.
        performance_metrics: Dict with throughput, hit rates, etc.
        iteration: Current iteration number.
        max_iterations: Maximum iterations allowed.

    Returns:
        Context dictionary ready for LLMProvider.generate().
    """
    return {
        "current_policy": current_policy,
        "recent_mutations": recent_mutations,
        "performance_metrics": performance_metrics,
        "iteration": iteration,
        "max_iterations": max_iterations,
    }


# Convenience function for quick testing
def test_provider() -> None:
    """Test that the provider can be initialized.

    This is used by the preflight check.
    """
    provider = LLMProviderFactory.create()
    print(f"Provider OK: {type(provider).__name__}")
    print(f"  Model: {provider.config.model}")
    print(f"  Temperature: {provider.config.temperature}")
    print(f"  Max tokens: {provider.config.max_tokens}")


if __name__ == "__main__":
    test_provider()
