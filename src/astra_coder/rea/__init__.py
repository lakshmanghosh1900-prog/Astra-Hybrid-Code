"""Stage 05b REA runtime gate, RBAC enforcement, and receipt/audit utilities."""

from .enforcement import require_stage05b_execution
from .gate import ReaGateResult, enforce_rea_gate
from .rbac import RbacDecision, evaluate_rbac
from .receipt import append_audit_event, build_execution_receipt, verify_event_chain

__all__ = [
    "RbacDecision",
    "evaluate_rbac",
    "ReaGateResult",
    "enforce_rea_gate",
    "require_stage05b_execution",
    "build_execution_receipt",
    "append_audit_event",
    "verify_event_chain",
]
