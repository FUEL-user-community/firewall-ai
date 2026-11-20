"""
Core Forge — Dual-Slot Self-Reincarnation, Constitutional Law Ring, and Shared State.
"""

from core.forge.laws import ConstitutionalError, validate_mutation_paths, validate_python_ast
from core.forge.state_store import SharedStateStore, get_shared_store

__all__ = [
    "ConstitutionalError",
    "validate_mutation_paths",
    "validate_python_ast",
    "SharedStateStore",
    "get_shared_store",
]
