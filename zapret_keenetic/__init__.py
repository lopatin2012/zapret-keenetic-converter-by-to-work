"""Flowseal winws to nfqws2-keenetic converter."""

from .converter import ConversionError, ConversionResult, ConverterSettings, convert
from .deployer import DeploymentError, DeploymentResult, DeploymentSettings, deploy_bundle
from .version import TARGET_NFQWS2_VERSION, TARGET_ZAPRET2_VERSION, __version__

__all__ = [
    "ConversionError",
    "ConversionResult",
    "ConverterSettings",
    "DeploymentError",
    "DeploymentResult",
    "DeploymentSettings",
    "TARGET_NFQWS2_VERSION",
    "TARGET_ZAPRET2_VERSION",
    "convert",
    "deploy_bundle",
    "__version__",
]
