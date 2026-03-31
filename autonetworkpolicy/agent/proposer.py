"""
Mutation DSL schema and proposer module for LLM-guided mutations.

This module defines the mutation dataclasses and the Proposer class that queries
LLMs to generate mutations for firewall rule optimization.

Mutation DSL:
- swap(i, j): Swap rules at indices i and j
- move_before(i, j): Move rule i before rule j
- merge_adjacent(i): Merge rule i with i+1 if compatible
- remove_shadowed(i): Remove rule i if fully shadowed by earlier rules
"""

from dataclasses import dataclass, field
from typing import Any, Optional

from .provider import LLMProvider, LLMProviderFactory


@dataclass
class Mutation:
    """Represents a mutation operation proposed by the LLM.

    Attributes:
        mutation_type: Type of mutation ("swap", "move_before", "merge_adjacent", "remove_shadowed")
        description: Human-readable explanation of the mutation
        operation: Dictionary with "name" and "args" keys describing the operation
        confidence: Optional confidence score from 0.0-1.0
    """

    mutation_type: str
    description: str
    operation: dict[str, Any]
    confidence: float = field(default=0.0)

    def __post_init__(self) -> None:
        """Validate mutation after initialization."""
        if not self.description:
            self.description = f"{self.mutation_type} operation"


class InvalidMutationError(Exception):
    """Raised when a mutation fails validation."""

    pass


class Proposer:
    """LLM-guided mutation proposer for firewall rule optimization.

    This class queries an LLM provider to generate mutations that improve
    firewall performance while maintaining security equivalence.

    Attributes:
        provider: LLMProvider instance for querying mutations
        system_prompt: Template prompt explaining the mutation DSL to the LLM
    """

    SYSTEM_PROMPT_TEMPLATE = """You are a firewall optimization expert specializing in nftables rulesets.

Your task is to analyze firewall policy data and propose a SINGLE mutation that improves performance while maintaining exact security equivalence.

=== MUTATION DSL ===

You must respond with a JSON object containing one of these mutation types:

1. SWAP(i, j) - Swap two rules
   {"mutation_type": "swap", "description": "Swap rules 5 and 12 to put high-hit rule earlier", "operation": {"name": "swap", "args": [5, 12]}}

2. MOVE_BEFORE(i, j) - Move rule i to before rule j
   {"mutation_type": "move_before", "description": "Move rule 8 before rule 3", "operation": {"name": "move_before", "args": [8, 3]}}

3. MERGE_ADJACENT(i) - Merge rule i with rule i+1 if they have same action
   {"mutation_type": "merge_adjacent", "description": "Merge rules 10 and 11 (both accept from same subnet)", "operation": {"name": "merge_adjacent", "args": [10]}}

4. REMOVE_SHADOWED(i) - Remove rule i if fully shadowed by earlier rules
   {"mutation_type": "remove_shadowed", "description": "Remove rule 15, shadowed by rule 7", "operation": {"name": "remove_shadowed", "args": [15]}}

5. CONSOLIDATE(i, j, ...) - Merge 2+ adjacent rules with same action and complementary CIDRs
   {"mutation_type": "consolidate", "description": "Consolidate rules 5-7 into a single rule", "operation": {"name": "consolidate", "args": [5, 6, 7]}}
   Requirements: All rules must have same action, same dst_ip, same protocol; src_ips must form a collapsible CIDR range

6. SPLIT(i, replacements) - Split one rule into more specific subnet rules
   {"mutation_type": "split", "description": "Split rule 10 into specific department subnets", "operation": {"name": "split", "args": [10], "replacements": [{"src_ip": "10.0.1.0/24", "dst_ip": "192.168.1.0/24", "action": "accept"}, {"src_ip": "10.0.2.0/24", "dst_ip": "192.168.1.0/24", "action": "accept"}]}}
   Requirements: All replacements must be subsets of original src_ip and dst_ip; max 5 replacements

=== CONSTRAINTS (FULL 5-TUPLE MODE v2) ===

- Rules are 0-indexed
- Index 0 ("ct state established,related accept") is FIXED - never move it
- Last rule (default-drop) is FIXED - never move it
- Mutations operate on the full 5-tuple: src_ip, dst_ip, src_port, dst_port, protocol
- Port ranges are tuples (min, max). None = any port.
- Protocol: 6=TCP, 17=UDP, 1=ICMP, 0=any
- Mutations must preserve exact packet-filtering equivalence across all 5 fields
- Return ONLY the JSON object, no markdown formatting

=== DECISION GUIDANCE ===

Consider these factors when proposing mutations:
- Rules with high hit counts should typically be moved earlier
- Rules with 0 hits may be candidates for removal
- Adjacent rules with same action and overlapping IP ranges may be mergeable
- Look for rules that are logically similar but separated by unrelated rules
- Rules with same IPs but different ports/protocols are NOT interchangeable
- Adjacent rules with same IPs AND same ports AND same protocol AND same action → merge candidates
- Port-specific rules (e.g., dport 80) should be ordered before broad port rules (any)

=== SEMANTIC AWARENESS ===

Rules may have semantic structure - departments, zones, application tiers.
Look for patterns:
- Rules sharing a subnet often belong to the same department/zone
- Port groupings indicate application tiers (80/443=web, 5432/3306=database)
- Comments (if present) reveal intent - use them to guide optimization
- Rules can be consolidated across semantic boundaries when the semantic grouping
  makes them redundant

When proposing mutations, explain the SEMANTIC REASON:
- "Rules 15-20 all serve the engineering department (10.3.0.0/16) and can be consolidated"
- "Rule 45 (guest zone) is shadowed by rule 12 (default deny to servers zone)"

Focus on SEMANTIC optimizations — ordering, consolidation, splitting. Shadow removal is already handled by algorithms.

Propose the single most impactful mutation based on the context below."""

    VALID_MUTATION_TYPES = {
        "swap",
        "move_before",
        "merge_adjacent",
        "remove_shadowed",
        "consolidate",
        "split",
    }

    def __init__(self, provider: Optional[LLMProvider] = None):
        """Initialize the proposer with an LLM provider.

        Args:
            provider: LLMProvider instance. If None, creates one using factory.

        Raises:
            ValueError: If provider cannot be created or configured.
        """
        if provider is None:
            provider = LLMProviderFactory.create()

        self.provider = provider

    def propose_mutation(self, context: dict[str, Any]) -> Optional[Mutation]:
        """Query LLM and return validated mutation.

        This method formats the context into a prompt, queries the LLM,
        validates the response, and returns a Mutation object if valid.

        Args:
            context: Dictionary containing:
                - current_policy: List of current firewall rules
                - recent_mutations: History of recent mutations
                - performance_metrics: Throughput, hit rates, etc.
                - iteration: Current iteration number
                - max_iterations: Maximum iterations allowed
                - rule_count: Total number of rules (for bounds checking)

        Returns:
            Mutation object if valid, None if invalid or LLM error.
        """
        try:
            # Get rule count from context for validation
            rule_count = context.get("rule_count", 0)
            if rule_count == 0 and "current_policy" in context:
                rule_count = len(context["current_policy"])

            # Query LLM for mutation
            response = self.provider.generate(context)

            # Validate the response structure
            if not self.validate_mutation(response, rule_count):
                return None

            # Extract and create Mutation object
            mutation = Mutation(
                mutation_type=response["mutation_type"],
                description=response.get("description", ""),
                operation=response["operation"],
                confidence=response.get("confidence", 0.0),
            )

            return mutation

        except Exception as e:
            # Log error but return None - caller decides whether to retry
            # In production, this should use proper logging
            print(f"Proposer error: {e}")
            return None

    def validate_mutation(self, mutation: dict[str, Any], rule_count: int) -> bool:
        """Validate mutation structure and bounds.

        Checks:
        - Required fields present
        - Mutation type is valid
        - Operation structure is correct
        - Indices are within bounds
        - Args have correct structure for mutation type

        Args:
            mutation: Dictionary containing mutation proposal from LLM
            rule_count: Total number of rules (for bounds checking)

        Returns:
            True if valid, False otherwise.
        """
        # Check required fields
        required_fields = {"mutation_type", "operation"}
        for field in required_fields:
            if field not in mutation:
                return False

        # Validate mutation type
        mutation_type = mutation["mutation_type"]
        if mutation_type not in self.VALID_MUTATION_TYPES:
            return False

        # Validate operation structure
        operation = mutation["operation"]
        if not isinstance(operation, dict):
            return False

        if "name" not in operation or "args" not in operation:
            return False

        if not isinstance(operation["args"], list):
            return False

        # Validate operation name matches mutation_type
        if operation["name"] != mutation_type:
            return False

        args = operation["args"]

        # Validate based on mutation type
        if mutation_type == "swap":
            # swap(i, j): Two indices, different, within bounds
            if len(args) != 2:
                return False
            i, j = args[0], args[1]
            if not (isinstance(i, int) and isinstance(j, int)):
                return False
            if not (0 <= i < rule_count and 0 <= j < rule_count):
                return False
            if i == j:
                return False

        elif mutation_type == "move_before":
            # move_before(i, j): Move rule i before rule j
            if len(args) != 2:
                return False
            i, j = args[0], args[1]
            if not (isinstance(i, int) and isinstance(j, int)):
                return False
            if not (0 <= i < rule_count and 0 <= j < rule_count):
                return False
            if i == j:
                return False

        elif mutation_type == "merge_adjacent":
            # merge_adjacent(i): Merge rule i with i+1, so i must be < rule_count - 1
            if len(args) != 1:
                return False
            i = args[0]
            if not isinstance(i, int):
                return False
            if not (0 <= i < rule_count - 1):  # Need i+1 to exist
                return False

        elif mutation_type == "remove_shadowed":
            # remove_shadowed(i): Remove rule i
            if len(args) != 1:
                return False
            i = args[0]
            if not isinstance(i, int):
                return False
            if not (0 <= i < rule_count):
                return False

        return True

    def format_prompt(self, context: dict[str, Any]) -> str:
        """Format context into LLM prompt.

        Creates a human-readable prompt from the context dictionary
        that helps the LLM understand the current state and propose
        an appropriate mutation.

        Args:
            context: Dictionary containing:
                - current_policy: List of current firewall rules
                - recent_mutations: History of recent mutations
                - performance_metrics: Throughput, hit rates, etc.
                - iteration: Current iteration number
                - max_iterations: Maximum iterations allowed

        Returns:
            Formatted prompt string for the LLM.
        """
        lines = []

        # Add header
        lines.append("=== CURRENT POLICY STATE ===\n")

        # Add current policy info
        current_policy = context.get("current_policy", [])
        rule_count = len(current_policy)
        lines.append(f"Total Rules: {rule_count}")
        lines.append(f"Protected Indices: 0 (conntrack), {rule_count - 1} (default-drop)\n")

        lines.append("Rule Summary:")
        display_limit = 35
        if rule_count <= display_limit:
            for i, rule in enumerate(current_policy):
                lines.append(f"  [{i}] {rule}")
        else:
            for i in range(min(30, rule_count)):
                lines.append(f"  [{i}] {current_policy[i]}")
            lines.append("  ...")
            for i in range(max(30, rule_count - 5), rule_count):
                lines.append(f"  [{i}] {current_policy[i]}")

        lines.append("")

        # Add performance metrics
        metrics = context.get("performance_metrics", {})
        if metrics:
            lines.append("=== PERFORMANCE METRICS ===")
            for key, value in metrics.items():
                if key not in ("hit_rates", "match_depth"):
                    lines.append(f"  {key}: {value}")
            if "match_depth" in metrics:
                lines.append(f"  match_depth: {metrics['match_depth']} (lower is better)")
            lines.append("")

        # Add hit rates if available
        hit_rates = metrics.get("hit_rates", {})
        if hit_rates:
            lines.append("=== RULE HIT RATES ===")
            # Sort by hit count descending to highlight hot rules
            sorted_hits = sorted(
                hit_rates.items(),
                key=lambda x: x[1] if isinstance(x[1], (int, float)) else 0,
                reverse=True,
            )
            for rule_idx, hits in sorted_hits[:10]:  # Top 10
                lines.append(f"  Rule {rule_idx}: {hits} hits")
            lines.append("")

        # Add recent mutation history
        recent_mutations = context.get("recent_mutations", [])
        if recent_mutations:
            lines.append("=== RECENT MUTATION HISTORY ===")
            for i, mut in enumerate(recent_mutations[-5:], 1):
                mut_type = mut.get("mutation_type", "unknown")
                desc = mut.get("description", "no description")
                outcome = mut.get("outcome", "unknown")
                score_change = mut.get("score_change", "N/A")
                lines.append(f"  {i}. {mut_type}: {desc}")
                lines.append(f"     Outcome: {outcome}, Score change: {score_change}")
            lines.append("")

        # Add iteration info
        iteration = context.get("iteration", 0)
        max_iterations = context.get("max_iterations", 100)
        lines.append(f"=== PROGRESS ===")
        lines.append(f"Iteration: {iteration}/{max_iterations}")
        lines.append("")

        # Add instructions
        lines.append("=== INSTRUCTIONS ===")
        lines.append("Propose ONE mutation that will improve firewall performance.")
        lines.append("Return ONLY a JSON object in the format specified in your system prompt.")

        return "\n".join(lines)

    def get_system_prompt(self) -> str:
        """Get the system prompt template for the LLM.

        Returns:
            The system prompt explaining the mutation DSL.
        """
        return self.SYSTEM_PROMPT_TEMPLATE


def validate_mutation_operation(operation: dict[str, Any], rule_count: int) -> bool:
    """Standalone validation function for mutation operations.

    This function can be used independently of the Proposer class
    to validate mutation dictionaries.

    Args:
        operation: Dictionary with "name" and "args" keys
        rule_count: Total number of rules

    Returns:
        True if valid, False otherwise.

    Examples:
        >>> validate_mutation_operation({"name": "swap", "args": [1, 2]}, 10)
        True
        >>> validate_mutation_operation({"name": "swap", "args": [1, 1]}, 10)
        False  # Same index
        >>> validate_mutation_operation({"name": "merge_adjacent", "args": [9]}, 10)
        False  # No rule 10 to merge with
    """
    if not isinstance(operation, dict):
        return False

    if "name" not in operation or "args" not in operation:
        return False

    name = operation["name"]
    args = operation["args"]

    if not isinstance(args, list):
        return False

    valid_types = {"swap", "move_before", "merge_adjacent", "remove_shadowed"}
    if name not in valid_types:
        return False

    # Validate based on operation type
    if name == "swap":
        if len(args) != 2:
            return False
        i, j = args[0], args[1]
        if not (isinstance(i, int) and isinstance(j, int)):
            return False
        if not (0 <= i < rule_count and 0 <= j < rule_count):
            return False
        if i == j:
            return False

    elif name == "move_before":
        if len(args) != 2:
            return False
        i, j = args[0], args[1]
        if not (isinstance(i, int) and isinstance(j, int)):
            return False
        if not (0 <= i < rule_count and 0 <= j < rule_count):
            return False
        if i == j:
            return False

    elif name == "merge_adjacent":
        if len(args) != 1:
            return False
        i = args[0]
        if not isinstance(i, int):
            return False
        if not (0 <= i < rule_count - 1):
            return False

    elif name == "remove_shadowed":
        if len(args) != 1:
            return False
        i = args[0]
        if not isinstance(i, int):
            return False
        if not (0 <= i < rule_count):
            return False

    return True


def create_mutation_context(
    current_policy: list[dict[str, Any]],
    recent_mutations: list[dict[str, Any]],
    performance_metrics: dict[str, Any],
    iteration: int,
    max_iterations: int,
) -> dict[str, Any]:
    """Create a properly formatted context dictionary for the proposer.

    Args:
        current_policy: List of current firewall rules
        recent_mutations: History of recent mutations with outcomes
        performance_metrics: Dict with throughput, hit rates, etc.
        iteration: Current iteration number
        max_iterations: Maximum iterations allowed

    Returns:
        Context dictionary ready for Proposer.propose_mutation()

    Example:
        >>> context = create_mutation_context(
        ...     current_policy=[{"action": "accept", "src": "10.0.0.0/8"}],
        ...     recent_mutations=[],
        ...     performance_metrics={"throughput": 1.5},
        ...     iteration=1,
        ...     max_iterations=100,
        ... )
    """
    return {
        "current_policy": current_policy,
        "recent_mutations": recent_mutations,
        "performance_metrics": performance_metrics,
        "iteration": iteration,
        "max_iterations": max_iterations,
        "rule_count": len(current_policy),
    }


# Convenience function for testing
def test_proposer() -> None:
    """Test that the proposer can be initialized.

    This is used by preflight checks and basic validation.
    """
    try:
        proposer = Proposer()
        print(f"Proposer OK: {type(proposer.provider).__name__}")

        # Test validation
        test_cases = [
            ({"name": "swap", "args": [1, 2]}, 10, True),
            ({"name": "swap", "args": [1, 1]}, 10, False),  # Same index
            ({"name": "swap", "args": [0, 10]}, 10, False),  # Out of bounds
            ({"name": "merge_adjacent", "args": [5]}, 10, True),
            ({"name": "merge_adjacent", "args": [9]}, 10, False),  # No rule 10
            ({"name": "remove_shadowed", "args": [5]}, 10, True),
            ({"name": "remove_shadowed", "args": [10]}, 10, False),  # Out of bounds
            ({"name": "move_before", "args": [5, 3]}, 10, True),
            ({"name": "invalid_op", "args": [1]}, 10, False),  # Invalid type
        ]

        for operation, rule_count, expected in test_cases:
            result = validate_mutation_operation(operation, rule_count)
            status = "✓" if result == expected else "✗"
            print(f"  {status} {operation} (count={rule_count}): {result} (expected {expected})")

    except Exception as e:
        print(f"Proposer test failed: {e}")
        raise


if __name__ == "__main__":
    test_proposer()
