"""Transport-neutral service boundaries for Angerona.

Domain code depends on these contracts rather than HTTP, queues, or a concrete
process model.  Local adapters can run in-process today; remote adapters can
serialize the same requests and responses without changing analysis logic.
"""

from .contracts import (
    AnalysisRequest,
    EvidenceEnvelope,
    ExecutionRequest,
    ServiceResponse,
    ServiceStatus,
    VerificationRequest,
)

__all__ = [
    "AnalysisRequest",
    "EvidenceEnvelope",
    "ExecutionRequest",
    "ServiceResponse",
    "ServiceStatus",
    "VerificationRequest",
]
