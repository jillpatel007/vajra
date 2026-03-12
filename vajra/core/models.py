from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# Block 2 - Enums


class CrownJewelTier(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class EdgeValidity(Enum):
    VALID = "valid"
    CONDITION_BLOCKED = "condition_blocked"
    ASSUMED_VALID = "assumed_valid"
    UNKNOWN = "unknown"


class NetworkValidity(Enum):
    REACHABLE = "reachable"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class RelationType(Enum):
    CAN_ASSUME = "can_assume"
    HAS_ROLE = "has_role"
    TRUSTS = "trusts"
    HAS_ACCESS = "has_access"
    CONTAINS_SECRET = "contains_secret"  # pragma: allowlist secret  # noqa: S105
    SUPPLY_CHAIN_RISK = "supply_chain_risk"
    MCP_TOOL_ACCESS = "mcp_tool_access"
    TRAINS_ON = "trains_on"
    CAN_ACT_AS = "can_act_as"
    CICD_PIPELINE = "cicd_pipeline"
    CROSS_ACCOUNT = "cross_account"


class AssetType(Enum):
    # AWS
    IAM_ROLE = "iam_role"
    IAM_USER = "iam_user"
    S3_BUCKET = "s3_bucket"
    EC2_INSTANCE = "ec2_instance"
    LAMBDA_FUNCTION = "lambda_function"
    SECRET = "secret"  # pragma: allowlist secret  # noqa: S105
    CONTAINS_SECRET = "contains_secret"  # pragma: allowlist secret  # noqa: S105
    RDS_DATABASE = "rds_database"
    # Azure
    SERVICE_PRINCIPAL = "service_principal"
    MANAGED_IDENTITY = "managed_identity"
    KEY_VAULT = "key_vault"
    BLOB_CONTAINER = "blob_container"
    # GCP
    SERVICE_ACCOUNT = "service_account"
    GCS_BUCKET = "gcs_bucket"
    # China clouds
    RAM_ROLE = "ram_role"
    OSS_BUCKET = "oss_bucket"
    # Kubernetes
    K8S_SERVICE_ACCOUNT = "k8s_service_account"
    K8S_CLUSTER_ROLE = "k8s_cluster_role"
    # AI / ML
    AI_AGENT = "ai_agent"
    MCP_SERVER = "mcp_server"
    ML_MODEL = "ml_model"
    ML_TRAINING_JOB = "ml_training_job"
    DATASET = "dataset"
    # Generic
    CICD_PIPELINE = "cicd_pipeline"


# Block 3 - CloudAsset


class CloudAsset(BaseModel):
    """A single cloud resource discovered by Vajra.

    frozen=True means no field can be changed after creation.
    Any tampering is detected by integrity_hash().
    """

    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    asset_type: AssetType
    provider: Literal[
        "aws",
        "azure",
        "gcp",
        "alibaba",
        "tencent",
        "huawei",
    ]
    region: str
    metadata: dict[str, object] = {}
    is_entry_point: bool = False
    is_crown_jewel: bool = False
    is_shadow_it: bool = False
    is_business_critical: bool = False
    crown_jewel_tier: CrownJewelTier | None = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)

    def integrity_hash(self) -> str:
        """SHA-256 fingerprint of this asset.

        If ANY field changes, this hash changes.
        Used to detect silent tampering.
        """
        return hashlib.sha256(self.model_dump_json().encode()).hexdigest()


# Block 4 - GraphEdge


@dataclass(frozen=True, slots=True)
class GraphEdge:
    """A relationship between two cloud assets.

    Represents one step in an attack path.
    frozen=True: cannot be modified after creation.
    slots=True: faster memory access, lower overhead.
    """

    source: str
    target: str
    relation: RelationType
    risk_weight: float
    conditions: tuple[str, ...] = ()
    iam_validity: EdgeValidity = EdgeValidity.ASSUMED_VALID
    network_validity: NetworkValidity = NetworkValidity.UNKNOWN

    @property
    def is_exploitable(self) -> bool:
        """True only if BOTH IAM and network allow this edge.

        One block = not exploitable.
        This prevents false positives where IAM allows
        but network blocks (or vice versa).
        """
        return (
            self.iam_validity == EdgeValidity.VALID
            and self.network_validity == NetworkValidity.REACHABLE
        )


# Block 5 - Module interface

__version__ = "0.1.0"

__all__ = [
    "AssetType",
    "CloudAsset",
    "CrownJewelTier",
    "EdgeValidity",
    "GraphEdge",
    "NetworkValidity",
    "RelationType",
]
