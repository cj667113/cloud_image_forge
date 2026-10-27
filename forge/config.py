"""Deployment settings; cloud credentials stay in the SDK credential chain."""
from dataclasses import dataclass, field
import os
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.getenv("FORGE_DATA_DIR", "data")).resolve())
    api_token: str = field(default_factory=lambda: os.getenv("API_TOKEN", ""))
    max_upload_gib: float = field(default_factory=lambda: float(os.getenv("FORGE_MAX_UPLOAD_GIB", "64")))
    max_virtual_gib: float = field(default_factory=lambda: float(os.getenv("FORGE_MAX_VIRTUAL_GIB", "2048")))
    allow_private_endpoints: bool = field(default_factory=lambda: os.getenv("FORGE_ALLOW_PRIVATE_ENDPOINTS", "false").lower() == "true")

    @property
    def max_upload_bytes(self) -> int:
        return int(self.max_upload_gib * 1024**3)
