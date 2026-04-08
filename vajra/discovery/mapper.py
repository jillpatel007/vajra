"""Universal discovery mapper — BaseDiscoverer + ASSET_MAPS.

Every cloud provider discoverer inherits from BaseDiscoverer.
__init_subclass__ auto-registers each discoverer in a central registry.

This is the plugin pattern: writing `class AWSDiscoverer(BaseDiscoverer)`
is all it takes — zero manual wiring. The registry tracks every
discoverer automatically.

ASSET_MAPS normalises CloudQuery table schemas into CloudAsset fields.
Each provider has different column names for the same concept.
The maps translate provider-specific JSON paths to our universal model.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from vajra.core.models import AssetType, CloudAsset

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ASSET_MAPS — per-provider column mapping
# ---------------------------------------------------------------------------
# Each provider returns different column names for the same concept.
# Example: AWS calls it "arn", Azure calls it "id", GCP calls it "name".
# These maps normalise that into CloudAsset fields.
#
# Format: { "provider": { "cloudquery_table": {
#     "id_column": str, "name_column": str, "asset_type": AssetType
# }}}

ASSET_MAPS: dict[str, dict[str, dict[str, Any]]] = {
    "aws": {
        "aws_iam_roles": {
            "id_column": "arn",
            "name_column": "role_name",
            "asset_type": AssetType.IAM_ROLE,
        },
        "aws_iam_users": {
            "id_column": "arn",
            "name_column": "user_name",
            "asset_type": AssetType.IAM_USER,
        },
        "aws_s3_buckets": {
            "id_column": "arn",
            "name_column": "name",
            "asset_type": AssetType.S3_BUCKET,
        },
        "aws_ec2_instances": {
            "id_column": "arn",
            "name_column": "instance_id",
            "asset_type": AssetType.EC2_INSTANCE,
        },
        "aws_lambda_functions": {
            "id_column": "arn",
            "name_column": "function_name",
            "asset_type": AssetType.LAMBDA_FUNCTION,
        },
        "aws_secretsmanager_secrets": {
            "id_column": "arn",
            "name_column": "name",
            "asset_type": AssetType.SECRET,
        },
    },
    "azure": {
        "azure_ad_service_principals": {
            "id_column": "id",
            "name_column": "display_name",
            "asset_type": AssetType.SERVICE_PRINCIPAL,
        },
        "azure_keyvault_vaults": {
            "id_column": "id",
            "name_column": "name",
            "asset_type": AssetType.KEY_VAULT,
        },
        "azure_storage_accounts": {
            "id_column": "id",
            "name_column": "name",
            "asset_type": AssetType.BLOB_CONTAINER,
        },
    },
    "gcp": {
        "gcp_iam_service_accounts": {
            "id_column": "unique_id",
            "name_column": "email",
            "asset_type": AssetType.SERVICE_ACCOUNT,
        },
        "gcp_storage_buckets": {
            "id_column": "id",
            "name_column": "name",
            "asset_type": AssetType.GCS_BUCKET,
        },
    },
    "alibaba": {
        "alibaba_ram_roles": {
            "id_column": "role_id",
            "name_column": "role_name",
            "asset_type": AssetType.RAM_ROLE,
        },
        "alibaba_oss_buckets": {
            "id_column": "name",
            "name_column": "name",
            "asset_type": AssetType.OSS_BUCKET,
        },
    },
    "tencent": {
        "tencent_cam_roles": {
            "id_column": "role_id",
            "name_column": "role_name",
            "asset_type": AssetType.RAM_ROLE,
        },
    },
    "huawei": {
        "huawei_iam_agencies": {
            "id_column": "id",
            "name_column": "name",
            "asset_type": AssetType.RAM_ROLE,
        },
    },
    "k8s": {
        "k8s_core_service_accounts": {
            "id_column": "uid",
            "name_column": "name",
            "asset_type": AssetType.K8S_SERVICE_ACCOUNT,
        },
    },
}


# ---------------------------------------------------------------------------
# BaseDiscoverer — auto-registering plugin base class
# ---------------------------------------------------------------------------


class BaseDiscoverer(ABC):
    """Base class for all cloud provider discoverers.

    How __init_subclass__ works:
        When Python sees `class AWSDiscoverer(BaseDiscoverer):`,
        it calls BaseDiscoverer.__init_subclass__(AWSDiscoverer).
        We use this to auto-register every discoverer in _registry.

    Why this pattern?
        Adding a new cloud provider = one new file that subclasses
        BaseDiscoverer. Zero changes to existing code. Zero imports
        to add. The registry discovers all providers automatically.
    """

    # Central registry: maps provider name → discoverer class
    _registry: dict[str, type[BaseDiscoverer]] = {}

    # Each subclass must set this to its provider name (e.g. "aws", "gcp")
    provider: str = ""

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Auto-register every subclass in the discoverer registry."""
        super().__init_subclass__(**kwargs)
        # Only register concrete discoverers that set a provider name
        if cls.provider:
            BaseDiscoverer._registry[cls.provider] = cls
            logger.debug("registered discoverer: %s → %s", cls.provider, cls.__name__)

    @abstractmethod
    def discover(self) -> list[CloudAsset]:
        """Discover cloud assets for this provider.

        Each subclass implements this to query CloudQuery DuckDB
        and return a list of CloudAsset objects.
        """

    @classmethod
    def get_registry(cls) -> dict[str, type[BaseDiscoverer]]:
        """Return all registered discoverers."""
        return dict(cls._registry)

    @classmethod
    def get_discoverer(cls, provider: str) -> type[BaseDiscoverer] | None:
        """Look up a discoverer by provider name."""
        return cls._registry.get(provider)
