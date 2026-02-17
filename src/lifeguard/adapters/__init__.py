"""Adapter layer for selected external modules."""

from .contract import (
    ADAPTER_CONTRACT_VERSION,
    AdapterActionRequest,
    AdapterActionResult,
    AdapterContractError,
    AdapterError,
    AdapterToolSchema,
    AdapterTrustMetadata,
    StableAdapterContract,
)
from .extracts_adapter import (
    AdapterModuleStatus,
    AdapterUnavailableError,
    LifeguardExtractsAdapterLayer,
)
from .langchain_compat import (
    LangChainCompatibilityAdapter,
    LangChainCompatibilityAdapterError,
)
from .langgraph_compat import (
    LangGraphCompatibilityAdapter,
    LangGraphCompatibilityAdapterError,
)
from .mcp_compat import (
    ModelContextProtocolCompatibilityAdapter,
    ModelContextProtocolCompatibilityAdapterError,
)

__all__ = [
    "ADAPTER_CONTRACT_VERSION",
    "AdapterActionRequest",
    "AdapterActionResult",
    "AdapterContractError",
    "AdapterError",
    "AdapterModuleStatus",
    "AdapterToolSchema",
    "AdapterTrustMetadata",
    "AdapterUnavailableError",
    "LifeguardExtractsAdapterLayer",
    "LangChainCompatibilityAdapter",
    "LangChainCompatibilityAdapterError",
    "LangGraphCompatibilityAdapter",
    "LangGraphCompatibilityAdapterError",
    "ModelContextProtocolCompatibilityAdapter",
    "ModelContextProtocolCompatibilityAdapterError",
    "StableAdapterContract",
]
