"""Strict recipes keep host paths and command options out of job inputs."""
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from .oci import OciConfig


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


MountPolicy = Literal["auto", "labels", "preserve"]


class MountPlanRequest(StrictModel):
    mount_policy: MountPolicy = "auto"


class ObjectLocation(StrictModel):
    url: str = Field(min_length=1, max_length=16384)
    endpoint_url: str | None = Field(default=None, max_length=2048)
    region: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9-]+$")


class FileEdit(StrictModel):
    path: str = Field(max_length=256)
    content: str = Field(max_length=262144)

    @field_validator("path")
    @classmethod
    def allowed_path(cls, value: str) -> str:
        fixed = {"/etc/fstab", "/etc/default/grub", "/etc/crontab",
                 "/etc/modules-load.d/cloud-image-forge.conf", "/etc/modprobe.d/cloud-image-forge.conf"}
        if value not in fixed and not re.fullmatch(r"/etc/(cron\.d/[A-Za-z0-9_-]+|systemd/system/[A-Za-z0-9_@.-]+\.service)", value):
            raise ValueError("Choose a supported configuration file, cron file, or systemd service unit")
        if ".." in value:
            raise ValueError("Parent paths are not allowed")
        return value

    @field_validator("content")
    @classmethod
    def text_only(cls, value: str) -> str:
        if "\0" in value:
            raise ValueError("Configuration must be text without NUL bytes")
        return value


class ServiceChange(StrictModel):
    name: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9_][A-Za-z0-9_@.:-]*\.(service|timer|socket|target)$")
    action: Literal["enable", "disable", "mask", "unmask"]


class PartitionChange(StrictModel):
    device: str = Field(pattern=r"^/dev/sda[1-9][0-9]*$")
    size_mib: int = Field(ge=32, le=2097152)


class BootMigration(StrictModel):
    enabled: bool = False
    esp_size_mib: int = Field(default=512, ge=512, le=2048)
    install_packages: bool = False


class FilesystemSize(StrictModel):
    device: str = Field(max_length=256, pattern=r"^/dev/(sda[1-9][0-9]*|[A-Za-z0-9_+.-]+/[A-Za-z0-9_+.-]+)$")
    size_mib: int = Field(ge=32, le=2097152)

    @field_validator("device")
    @classmethod
    def no_relative_components(cls, value: str) -> str:
        if any(component in {".", ".."} for component in value.split("/")):
            raise ValueError("Filesystem sizes must name an inspected device, without relative path components")
        return value


class StorageRebuild(StrictModel):
    enabled: bool = False
    sizes: list[FilesystemSize] = Field(default_factory=list, max_length=128)

    @model_validator(mode="after")
    def unique_filesystems(self):
        devices = [item.device for item in self.sizes]
        if len(devices) != len(set(devices)):
            raise ValueError("Each filesystem can have one target size")
        return self


class PlatformMigration(StrictModel):
    enabled: bool = False
    # Omitted strategy preserves the meaning of existing saved recipes. The UI
    # explicitly supplies the selected preparation or preservation strategy.
    strategy: Literal["preserve", "reconfigure"] = "reconfigure"
    source: Literal["unknown", "vm", "bare_metal"] = "vm"
    target: Literal["vm", "bare_metal"] = "bare_metal"
    boot_attachment: Literal["paravirtualized", "iscsi"] = "iscsi"
    network_attachment: Literal["paravirtualized", "accelerated", "vfio"] = "vfio"
    nic_driver: Literal["auto", "ixgbe", "ixgbevf", "i40e", "iavf", "mlx4_en", "mlx5_core", "bnxt_en"] | None = None
    install_packages: bool = False
    configure_network: bool = True
    configure_serial_console: bool = True

    @model_validator(mode="after")
    def migration_direction(self):
        if self.strategy == "preserve":
            for name in ("install_packages", "configure_network", "configure_serial_console"):
                if name in self.model_fields_set and getattr(self, name):
                    raise ValueError("Preserve and validate cannot enable " + name + "; select Reconfigure to change hardware settings")
                setattr(self, name, False)
        return self


class SSHUser(StrictModel):
    username: str = Field(min_length=1, max_length=32, pattern=r"^[a-z_][a-z0-9_-]{0,31}$")
    create: StrictBool = False
    authorized_keys: list[str] = Field(min_length=1, max_length=32)

    @field_validator("username")
    @classmethod
    def exact_username(cls, value: str) -> str:
        from .ssh_access import USERNAME
        if not USERNAME.fullmatch(value):
            raise ValueError("Use a Linux username of 1–32 lowercase letters, digits, underscores or hyphens")
        return value

    @field_validator("authorized_keys")
    @classmethod
    def public_keys(cls, values: list[str]) -> list[str]:
        from .ssh_access import validate_public_key
        return [validate_public_key(value) for value in values]

    @model_validator(mode="after")
    def non_admin_creation(self):
        if self.create and self.username == "root":
            raise ValueError("Creating root is unsupported; choose an existing account")
        return self


class SSHAccess(StrictModel):
    disable_password_auth: StrictBool = False
    users: list[SSHUser] = Field(default_factory=list, max_length=16)

    @model_validator(mode="after")
    def unique_users(self):
        usernames = [user.username for user in self.users]
        if len(usernames) != len(set(usernames)):
            raise ValueError("Configure each SSH username once")
        return self


class Recipe(StrictModel):
    target: Literal["oci", "aws", "azure", "gcp", "generic"] = "oci"
    output_format: Literal["qcow2", "raw", "vhd", "gcp", "oci"] = "qcow2"
    disk_size_gib: float | None = Field(default=None, gt=0, le=2048)
    partition_changes: list[PartitionChange] = Field(default_factory=list, max_length=128)
    expand_partition: str | None = Field(default=None, pattern=r"^/dev/sda[1-9][0-9]*$")
    expand_lv: str | None = Field(default=None, pattern=r"^/dev/[A-Za-z0-9_+.-]+/[A-Za-z0-9_+.-]+$")
    files: list[FileEdit] = Field(default_factory=list, max_length=100)
    services: list[ServiceChange] = Field(default_factory=list, max_length=100)
    packages_install: list[str] = Field(default_factory=list, max_length=100)
    packages_remove: list[str] = Field(default_factory=list, max_length=100)
    kernel_default: str | None = Field(default=None, max_length=256, pattern=r"^/boot/vmlinuz-[A-Za-z0-9_.+-]+$")
    kernel_args: str | None = Field(default=None, max_length=4096)
    rebuild_initramfs: bool = False
    regenerate_grub: bool = False
    sparsify: bool = True
    compress: bool = True
    allow_network: bool = False
    boot_migration: BootMigration | None = None
    storage_rebuild: StorageRebuild | None = None
    storage_resize: StorageRebuild | None = None
    platform_migration: PlatformMigration | None = None
    ssh_access: SSHAccess | None = None
    mount_policy: MountPolicy = "auto"
    oci: OciConfig | None = None

    @field_validator("packages_install", "packages_remove")
    @classmethod
    def package_names(cls, values: list[str]) -> list[str]:
        if any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_:~=-]{0,159}", item) for item in values):
            raise ValueError("Use package names or versions, without paths, wildcards, or command options")
        return values

    @field_validator("kernel_args")
    @classmethod
    def single_line(cls, value: str | None) -> str | None:
        if value is not None and any(c in value for c in "\r\n\0"):
            raise ValueError("Boot parameters must be a single line")
        return value

    @model_validator(mode="after")
    def compatible_recipe(self):
        if (self.platform_migration and self.platform_migration.enabled
                and self.platform_migration.strategy == "preserve" and self.oci and self.oci.guest.prepare):
            raise ValueError("Preserve and validate requires OCI guest preparation disabled; select Validate only or Reconfigure")
        if self.oci is not None and self.target != "oci":
            raise ValueError("OCI capabilities can be applied only to an OCI export")
        if self.output_format == "oci" and (self.target != "oci" or self.oci is None):
            raise ValueError("An OCI image archive requires the Oracle Cloud target and OCI settings")
        expected = {"aws": "raw", "azure": "vhd", "gcp": "gcp"}
        if self.target == "oci" and self.output_format not in {"qcow2", "oci"}:
            raise ValueError("oci requires the qcow2 or oci export preset")
        if self.target in expected and self.output_format != expected[self.target]:
            raise ValueError(f"{self.target} requires the {expected[self.target]} export preset")
        if self.packages_install and not self.allow_network:
            raise ValueError("Enable guest network access to install packages from guest repositories")
        devices = [c.device for c in self.partition_changes]
        if len(devices) != len(set(devices)) or self.expand_partition in devices:
            raise ValueError("Each partition can have one resize action")
        if self.storage_rebuild and self.storage_rebuild.enabled and (self.partition_changes or self.expand_partition or self.expand_lv):
            raise ValueError("Filesystem rebuild cannot be combined with direct partition or LV expansion actions")
        if self.storage_resize and self.storage_resize.enabled and (self.partition_changes or self.expand_partition or self.expand_lv or (self.storage_rebuild and self.storage_rebuild.enabled)):
            raise ValueError("Automatic filesystem sizing cannot be combined with legacy rebuild, partition or LV actions")
        paths = [f.path for f in self.files]
        if len(paths) != len(set(paths)):
            raise ValueError("Each configuration file can be edited once")
        if set(self.packages_install) & set(self.packages_remove):
            raise ValueError("A package cannot be both installed and removed")
        return self


class OciPlanRequest(StrictModel):
    oci: OciConfig
    allow_network: bool = False
    boot_migration: BootMigration | None = None
    platform_migration: PlatformMigration | None = None
    mount_policy: MountPolicy = "auto"


class UefiPlanRequest(StrictModel):
    boot_migration: BootMigration
    allow_network: bool = False


class StoragePlanRequest(StrictModel):
    storage_rebuild: StorageRebuild | None = None
    storage_resize: StorageRebuild | None = None
    disk_size_gib: float | None = Field(default=None, gt=0, le=2048)
    mount_policy: MountPolicy = "auto"

    @model_validator(mode="after")
    def one_sizing_method(self):
        if (self.storage_rebuild is None) == (self.storage_resize is None):
            raise ValueError("Provide exactly one storage sizing request")
        return self


class PlatformPlanRequest(StrictModel):
    platform_migration: PlatformMigration
    allow_network: bool = False
    target: Literal["oci", "aws", "azure", "gcp", "generic"] = "oci"
    oci: OciConfig | None = None
    boot_migration: BootMigration | None = None
    mount_policy: MountPolicy = "auto"


class DestinationSelection(StrictModel):
    profile_id: str = Field(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9:_.-]+$")
    source: Literal["unknown", "vm", "bare_metal"] = "unknown"
    strategy: Literal["reconfigure", "preserve"] = "reconfigure"
    nic_driver: Literal["auto", "ixgbe", "ixgbevf", "i40e", "iavf", "mlx4_en", "mlx5_core", "bnxt_en"] | None = None


class OciSchemaRequest(StrictModel):
    schema_data: dict = Field(alias="schema")
