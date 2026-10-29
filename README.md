# Cloud Image Forge

Cloud Image Forge is a self-hosted web application for editing offline Linux virtual machine images. Import a local disk image or an object from S3, inspect its filesystems, change guest configuration, then download a new image or upload it to an S3-compatible endpoint. Each build starts from an immutable imported source.

The application includes a FastAPI service, a dependency-free browser interface, a persistent job queue, and a Linux image engine built on QEMU and libguestfs. Disk operations run inside a libguestfs appliance, without mounting guest filesystems or activating guest LVM volumes on the host.

## Start with Docker

Use a **Linux x86_64 or ARM64 host** with Docker Engine and Docker Compose. Both can inspect, edit configuration files, resize supported filesystems and export x86_64 or ARM64 Linux images. Operations that execute guest programs need a worker matching the guest architecture. Budget several gigabytes of RAM and enough storage for the source, working copies, and output. RAW and fixed VHD exports can approach the full virtual disk size, regardless of how small the input QCOW2 file is.

```sh
cp .env.example .env
docker compose up --build -d
```

Open **http://localhost:8080**. The default configuration binds only to loopback and uses software emulation, so it does not need `/dev/kvm`, privileged mode, or access to host disks. The first build includes a Linux kernel and image tooling and will take longer than a typical web application image.

For faster filesystem rebuilds on a host with usable KVM, set `FORGE_KVM_GID` in `.env` to the output of `stat -c '%g' /dev/kvm`, then start with `docker compose -f compose.yaml -f compose.kvm.yaml up --build -d`. This supplies only the KVM device and its group; the service still runs without Linux capabilities or privileged mode. A host without working KVM should use the standard Compose file.

The Dockerfile supports native `linux/amd64` and `linux/arm64` builds, selecting the appropriate appliance kernel and QEMU packages. Compose uses the host's native platform. Package installation, service actions, SSH access changes, initramfs/GRUB regeneration and guest preparation require a matching architecture worker; the API rejects a mismatch before queueing a build. File-only edits and supported disk operations remain available across architectures. See [architecture support and deployment choices](docs/image-architectures.md). Docker Desktop adds a Linux VM; its image engine configurations have not been validated. The API and UI can be developed on macOS without the image tools.

The named `forge-data` volume stores imported images, jobs, build outputs, and metadata. `docker compose down` preserves it. Do not use `docker compose down -v` if you need to retain your images. Run **one API process and one replica per data directory**; an exclusive workspace lock rejects a second process using the same directory.

## Import, customize, export

1. Start at **Source**. Import an offline local file, enter an `s3://bucket/path/image.qcow2` or public/presigned HTTPS URL, or select a previously imported image. Custom S3 endpoints and regions are supported; credentials come from the server's AWS SDK configuration.
2. Continue to **Inspect** when import finishes. Review the operating system, disk capacity, partitions, filesystems, detected boot support, and warnings.
3. Use **Next** through **Storage**, **Startup**, **Access**, **Mounts**, and **Boot & kernel**. Set the changes you need or keep the existing settings. **Back** and the available step buttons let you revisit choices without clearing them.
4. Choose the provider and output format in **Destination**, with optional VM/bare-metal preparation. Oracle Cloud adds an **OCI compatibility** step for capability settings and guest preparation.
5. Check the changes and edited configuration files in **Review**. Use each card's **Edit** action to revise them, then select **Build image**.
6. **Build & export** shows progress and logs. A successful build opens **Exports** (`#artifacts`) and focuses the new image. Download it locally or upload it to S3 using an optional custom endpoint. Open **Details** for its manifest and any OCI configuration. Failed builds remain in the wizard for review and retry.

**Exports** keeps download and S3 upload actions beside each file. Open **Details** for the manifest, OCI configuration, checksum, and warnings. **Activity** separates running and queued work from searchable history, with status and operation filters. Open a job to read its log or return to its source/export; polling preserves open logs and your reading position.

The wizard keeps your choices while you navigate. Its warm neutral, charcoal, and red palette takes cues from Oracle/OCI; Cloud Image Forge is an independent application. Help buttons work on hover, keyboard focus, or tap. Required errors and migration limits remain visible. Inspection, field validation, and required migration or OCI checks must finish before the relevant step can continue.

Images must be shut down before export from the source hypervisor. Supported inputs are standalone **QCOW2, RAW, and fixed/dynamic VHD** disk files. The importer also accepts the reference project's two-member OCI export archive: regular root-level files named exactly `output.QCOW2` and `image_metadata.json`. It retains the metadata with the source and edits the extracted disk; it does not generate a new OCI metadata bundle on export.

VMDK, VHDX, general OVA/tar archives, backing-file chains, encrypted disks, multidisk guests, and multiple operating systems are unsupported. Extract or convert these to a supported standalone disk before import. The engine does not guess missing disks or decryption keys, and all configured local guest filesystems must be available.

### Boot detection

**Inspect** and **Boot & kernel** show **UEFI**, **legacy BIOS**, **dual**, or **unknown**, with the disk and loader evidence behind the result. Inspection checks EFI system partitions even when they are absent from `fstab`, validates EFI applications matching the x86_64 or ARM64 guest, and checks installed x86 GRUB BIOS structures. ARM64 requires an existing ARM64 UEFI boot chain. GPT, an empty EFI partition, or a boot-sector signature alone does not establish a boot mode. Unknown means the supported checks could not establish a mode; it does not prove the image cannot boot.

One detected firmware mode initializes the OCI firmware choice when the selected schema permits it. Dual-mode images require an explicit choice, and OCI preparation checks the selected modes against the detected support. This is offline evidence, not the VM's last firmware setting or a successful boot test. Firmware NVRAM is outside the disk image; vendor-only EFI paths may require a destination boot entry. See [detection and validation limits](docs/architecture.md#boot-mode-evidence).

Use **Refresh inspection** for older imports or to rerun detection against the preserved source without uploading it again. The API is `POST /api/images/{image_id}/inspect`; it returns a job with HTTP 202. Refreshing preserves the source and the editor draft. The previous inspection remains available if refresh fails, and new builds and OCI plans wait while refresh is queued or running.

### Add UEFI support to a BIOS image

The **Boot & kernel** step offers explicit **BIOS-to-UEFI migration** with a preview of changes and blockers. It supports eligible x86_64 Debian/Ubuntu, Enterprise Linux 9/10 derivatives, and Fedora 34+ images with detected BIOS support and suitable kernels, filesystems, and GRUB tooling. Refresh older imports to collect the migration prerequisites.

The preview uses the imported source. Storage and package edits run first during a build, then migration is replanned against the changed working disk; those edits can change eligibility and final capacity.

Migration runs on the working copy. It reuses one suitable FAT32 EFI system partition without formatting it, or grows the disk and appends a new ESP (512 MiB by default, plus alignment space). Existing partitions stay in place. It installs an EFI fallback loader, updates the ESP's UUID mount in `fstab`, regenerates GRUB configuration, and checks that BIOS structures and UEFI support remain detectable. Previous EFI files, `fstab`, and GRUB configuration are backed up inside the output guest.

The partition table remains GPT or MBR; MBR requires a free primary slot and capacity below its addressing limit. Hybrid tables, extended/logical MBR layouts, ambiguous ESPs, unsupported boot filesystems, and missing kernel EFI support produce blockers. Required guest packages need migration package permission; the wizard enables repository access when those selected changes require downloads. RPM migrations reinstall package-provided EFI GRUB; Debian/Ubuntu can use existing EFI tooling offline.

Boot the result with **Secure Boot disabled** and test both desired firmware modes. Firmware NVRAM is not changed, and future package upgrades may require refreshing the fallback loader. OCI firmware selection can use the planned migration, but publication requires UEFI evidence in the final image. OCI's Linux import guide still specifies BIOS source requirements while its capability schema exposes UEFI; validate the imported image and intended launch configuration in OCI. [OCI Linux import requirements](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/importingcustomimagelinux.htm), [OCI image capabilities](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/configuringimagecapabilities.htm)

### Guest changes

| Area | Available operations |
| --- | --- |
| Storage | Grow partitions and LVM; shrink direct ext2/3/4 partitions; rebuild supported GPT/UEFI XFS/ext filesystems and simple LVM into a smaller disk |
| Startup | Explore systemd dependencies and start ordering; enable, disable, mask, or unmask units; edit custom `.service` units |
| Scheduling | Edit `/etc/crontab` and files in `/etc/cron.d/` |
| SSH access | Disable password and keyboard-interactive login; append public keys to existing users or create a user with keys |
| Mounts | Edit `/etc/fstab` using the inspected contents as a starting point |
| Boot | Edit `/etc/default/grub`, change kernel arguments, regenerate GRUB configuration; add UEFI support to eligible BIOS images |
| Kernel | Install/remove packages, choose a supported installed default kernel, rebuild initramfs |
| Modules | Edit `/etc/modules-load.d/cloud-image-forge.conf` and `/etc/modprobe.d/cloud-image-forge.conf` |
| Output | Optional sparsification, QCOW2 compression, conversion, comparison, SHA-256 hashing |

The wizard enables guest repository access automatically for selected package operations or permitted preparation steps that require downloads. Unchanged images and preparation with all prerequisites already present remain offline. API clients retain explicit `allow_network` control, which defaults to false. Package repositories and package names belong to the guest distribution. A new kernel must be compatible with the guest's bootloader, filesystem, and destination hypervisor; selecting a provider preset does not install or configure that provider's agent automatically. Default-kernel selection currently requires the guest's `grubby` command. Initramfs rebuilding uses `dracut` or `update-initramfs`; GRUB regeneration uses `update-grub` or `grub2-mkconfig`. Unsupported guest tooling produces an explicit job error.

In **Access**, choose **Disable SSH password login** to disable password and keyboard-interactive authentication. **Add user keys** accepts pasted OpenSSH public keys or `.pub` uploads for an existing account; choose **Create this user** for a new account with a home directory, no usable password and no added administrator privileges. Existing keys are preserved and duplicates are skipped. Keep a working key or provider key provisioning available before disabling password login. SSH changes require a matching architecture worker and supported guest OpenSSH tools. See [SSH access behavior and limits](docs/ssh-access.md).

In **Startup**, find a unit such as `sshd.service` in **Service chain** to see a connected tree of its configured start order or dependencies. Small chains expand automatically; **Expand all** exposes the full reachable inventory, with shared references and cycles marked separately. The unit count shows how much of the chain is visible. Click a row to inspect its details without losing your place, or choose **Trace from here** to make it the root. Targets, sockets, and other connecting unit types remain in the tree. **Service changes** holds enable, disable, mask, and unmask actions separately from browsing.

The tree describes the imported source, including unit files, drop-ins, aliases, and enablement links. It does not reflect draft edits or supply measured `systemd-analyze blame` timings. Runtime/generated units and implicit dependencies are not synthesized; conditions are not evaluated. **Dependencies** follows requirements and wants; lifecycle, conflict, and failure relationships remain in unit details. Refresh inspection for images imported before this feature. A partial source inventory is labeled explicitly.

**XFS cannot shrink in place.** Storage combines disk capacity and filesystem sizes in one card. Choose **Automatic** or **Custom size**; Automatic keeps the disk unless the selected filesystems need more room. Turn on **Resize filesystems**, adjust sizes in GiB or MiB, then choose **Fit to filesystems** to minimize the outer disk. The fit action uses the server's layout plan and rechecks the resulting size. Bars show used space and the reduction; **Check sizes** shows blockers before building. Growth extends the required partitions, LVM containers and filesystems automatically while retaining their identities. A size reduction selects the supported rebuild path, restores files and verifies contents and metadata. It supports the Oracle Linux pattern in the supplied example: EFI, XFS `/boot`, and ordinary XFS logical volumes in one LVM volume group. Disk capacity accepts GiB or decimal GB. Layout details show the planned disk structure; partition and LVM expansion are inferred from the filesystem targets. Compressed output size is unknown until export.

The rebuild preserves filesystem UUIDs/labels, ownership, ACLs, extended attributes, SELinux labels, GPT identifiers, and EFI bytes. It creates new internal LVM IDs while preserving VG/LV names. It is restricted to supported single-disk GPT/UEFI layouts, Linux kernels 5.15 or newer, direct XFS/ext filesystems and one ordinary LVM PV/VG. BIOS/dual boot, complex LVM, encryption, unaccounted filesystems and quota/project-ID layouts block this workflow. Verified installer mount aliases and exact generated GRUB LVM search-hint blocks are normalized to preserved filesystem UUIDs before rebuilding; other internal LVM-ID pins remain blockers. Required space is checked, and failures do not publish an artifact. Existing API recipes using direct partition resize fields remain supported. See [storage and migration workflows](docs/storage-and-platform.md) and the [libguestfs resize documentation](https://libguestfs.org/virt-resize.1.html).

### VM and bare-metal preparation

Enable **Hardware compatibility** in **Destination** and select a destination profile. **Prepare for destination** applies documented boot/network defaults automatically; **Preserve & validate** checks an already-prepared image. Advanced settings retain explicit overrides. Preservation checks offline prerequisites and requires OCI guest preparation set to **Validate only**. Unknown evidence remains a blocker. Explicit edits in other steps, including the separate Mounts policy, still apply and are checked afterward. Existing recipes without a strategy retain reconfiguration behavior.

Preparation checks every installed non-rescue kernel, adapts boot transport arguments, rebuilds generic initramfs, and optionally replaces network profiles with DHCP and enables a serial console. Automatic bare-metal NIC preparation includes the supported physical drivers verified across all selected kernels; an explicit NIC remains available. Existing guest configuration is backed up in the output. The source machine type can remain unspecified. ARM64 bare-metal preparation requires existing UEFI and ACPI/iBFT evidence and remains experimental. The [VM3 audit and preservation rules](docs/storage-and-platform.md#optional-firmware-discovery-and-local-root-discovery) explain why a native OCI image can already boot on both VM and bare-metal hardware, including retained optional iSCSI discovery.

**Mounts** automatically resolves local references to the actual filesystem UUIDs, including Ubuntu installer by-id/by-uuid aliases. Filesystem UUIDs are retained across copies and supported rebuilds; references are reconciled and checked again before export. **Prefer labels** uses unique existing labels with visible UUID fallbacks for missing or unusable labels. No labels or UUIDs are created. Select **Mount references → Keep current** to retain the original `fstab`. Ambiguous or conflicting mappings require review instead of guessed replacements. See [automatic mount behavior](docs/storage-and-platform.md#automatic-mount-references).

The bare-metal profile is experimental UEFI/iSCSI preparation and requires the target firmware to supply valid iBFT/iSCSI boot information. It does not copy hardcoded addresses, IQNs, or initiator identities from the reference scripts. **OCI documents BYOI to bare metal as unsupported.** Preparing the disk does not establish provider support or a successful hardware boot. This application accepts captured disk images; it does not capture a running physical host or provision a bare-metal server. See [OCI BYOI limitations](https://docs.oracle.com/en-us/iaas/Content/Compute/References/bringyourownimage.htm) and [workflow details](docs/storage-and-platform.md).

### Export presets

| Preset | Artifact | Destination preparation still required |
| --- | --- | --- |
| Oracle Cloud | Standalone QCOW2 with zlib compression and 128 KiB clusters when compression is enabled | Check firmware, launch mode, storage/network drivers, cloud agent, and supported shape |
| AWS EC2 | RAW disk image | Use VM Import/Export with its IAM role, supported OS/kernel, boot mode, and S3 region requirements |
| Microsoft Azure | Fixed VHD with virtual capacity aligned to 1 MiB | Verify Hyper-V drivers, provisioning agent, generation, and Azure guest preparation |
| Google Cloud | Gzip-compressed GNU tar containing `disk.raw` | Copy to Cloud Storage, prepare guest environment, and create a Compute Engine image |
| Generic | QCOW2, RAW, or fixed VHD | Match the destination hypervisor's requirements |

These presets produce **import-format candidates**, not cloud certification. The application does not register images, create virtual machines, verify licensing, or prove that an artifact boots. Test an import and launch in the destination account before replacing a working image. OCI metadata bundles (`.oci`) are not generated; a standalone QCOW2 does not carry a separate source `image_metadata.json` into the imported image's launch settings. OCI's Native import recommendation specifically applies to QCOW2 images exported from OCI. [OCI import documentation](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/custom-images-import.htm)

Provider requirements change. Check the current [AWS VM Import/Export requirements](https://docs.aws.amazon.com/vm-import/latest/userguide/prerequisites.html), [Azure Linux image preparation](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/create-upload-generic), and [Google Cloud manual disk import requirements](https://docs.cloud.google.com/compute/docs/import/import-existing-image) for your source OS and destination.

### OCI compatibility and guest preparation

The **OCI compatibility** step exposes all 13 image capability keys in Oracle's published global schema: firmware, launch mode, NIC and three storage attachment types, consistent volume naming, PV encryption/attachment version, iSCSI multipath, IPv6-only, AMD SEV, and Secure Boot. Enum controls distinguish allowed choices from the preferred choice. Secure Boot stays disabled because OCI custom images do not support it.

**Accelerated PV** is available for networking and launch mode, including bare-metal-to-VM preparation. The reviewed E6 Ax VM uses VirtIO networking and VirtIO SCSI storage; the reviewed E5 bare-metal host uses `mlx5_core` with firmware-discovered iSCSI boot. Shape entries enforce the corresponding networking and driver requirements. The reference catalog includes newer API values, so load the destination region's global schema before applying exported capabilities. See [reviewed hardware and preparation choices](docs/oci-compatibility.md#reviewed-e6-ax-vm-and-e5-bare-metal-configurations).

Enable OCI preparation, select the capabilities, and use **Preview changes** to review guest changes and blockers before building. Preparation checks boot support and selected device drivers, and can configure initramfs, supported networking, OCI cloud-init discovery, and a serial console. Explicit BIOS-to-UEFI migration is available from **Boot & kernel** when the source is eligible. Package installation follows the selected preparation or migration option; the wizard infers required network access, while API clients supply `allow_network` explicitly. Unsupported layouts, missing required boot support, and incompatible advanced capabilities produce blockers rather than an image advertised as ready.

You can load a global schema downloaded from the destination region to use its current keys and values. Additional schema keys appear in the editor and export, with an explicit warning when Forge has no guest preparation adapter for them. Firmware and architecture still have to match the source guest; selecting a capability cannot translate an x86_64 image into an Arm image.

Optional import metadata includes compartment, namespace/bucket/object or object URI, display name, OS/version, import mode, tags, and shape compatibility with OCPU/memory bounds. These are exported configuration. After a successful OCI build, download **OCI configuration** alongside the QCOW2. The configuration ZIP contains CLI JSON, schema data, optional instance launch settings, shape entries, the profile, and operator instructions. It is **not** an `.oci` disk-image archive, and creating it performs no cloud import or launch. A supplied presigned object URI remains in the ZIP and profile, so keep those files private.

See the [OCI compatibility reference](docs/oci-compatibility.md) for the exact capability keys, guest-versus-cloud behavior, import/API field mapping, and validation limits.

## S3-compatible storage

The browser provides object locations and optional endpoint/region values. AWS access keys are configured on the server through the SDK credential chain; they are never fields in the browser UI or saved in a build recipe.

For a simple local deployment, set `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optionally `AWS_SESSION_TOKEN` in `.env`. For production, inject credentials through your container platform or configure a workload role. The default Compose configuration disables EC2 metadata credential lookup; set `AWS_EC2_METADATA_DISABLED=false` only when using an EC2 instance role intentionally.

Custom endpoints can use services such as MinIO or OCI's S3-compatible Object Storage API. Set the service-specific endpoint URL in the import or upload form and use the corresponding server-side credentials. HTTPS certificate verification remains enabled. Private or loopback endpoints require the server operator to set `FORGE_ALLOW_PRIVATE_ENDPOINTS=true`; this allows access to private network destinations and should only be enabled on a trusted deployment.

For profile-based credentials, mount an appropriate AWS configuration directory read-only into `/home/forge/.aws`, with files readable by UID 10001. Never bake credentials into the image or place them in the repository.

## Access and resource configuration

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `API_TOKEN` | Empty | Shared access token; the UI exchanges it for a session cookie |
| `FORGE_BIND_ADDRESS` | `127.0.0.1` | Host interface published by Compose |
| `FORGE_PORT` | `8080` | Host port published by Compose |
| `FORGE_DATA_DIR` | `/data` in Docker | Durable application and image storage |
| `FORGE_MAX_UPLOAD_GIB` | `64` | Maximum received file/object size |
| `FORGE_MAX_VIRTUAL_GIB` | `2048` | Maximum expanded virtual disk capacity |
| `FORGE_ALLOW_PRIVATE_ENDPOINTS` | `false` | Permit trusted private object-storage destinations |
| `LIBGUESTFS_BACKEND_SETTINGS` | `force_tcg` | Software emulation; use `force_kvm` only with KVM configured |
| `FORGE_KVM_GID` | unset | Host KVM device group; required by the optional `compose.kvm.yaml` |

Set a long random `API_TOKEN` before publishing the service beyond localhost. For remote use, place it behind an HTTPS reverse proxy with an upload limit and timeout suitable for large disk images. Forward the original `Host` and scheme, and configure Uvicorn's `FORWARDED_ALLOW_IPS` to trust only your proxy's address so HTTPS sessions and same-origin checks work correctly. This is a single-operator tool; the shared token does not provide tenant isolation or per-user permissions. Imported disks contain executable guest software; use trusted source images and a dedicated image-build host.

Jobs are serialized because each appliance and disk conversion consumes substantial memory and I/O. Interrupting the server interrupts in-flight jobs; interrupted work is marked failed on startup and can be submitted again. Startup recovery removes incomplete imports and unpublished build directories while retaining completed source images and artifacts. Maintain sufficient free disk space for concurrent stored images as well as one active working set. Multipart local uploads are first spooled to `/data/tmp` and then copied into the source directory, so allow room for both copies on the data volume during import. The libguestfs appliance cache remains in the container's `/var/tmp/forge` directory.

### Optional KVM acceleration

On a Linux x86_64 or ARM64 host with matching hardware virtualization and an accessible `/dev/kvm`, use the included `compose.kvm.yaml`. Set `FORGE_KVM_GID` in `.env` to the host device's group ID (`stat -c '%g' /dev/kvm`), then start:

```sh
docker compose -f compose.yaml -f compose.kvm.yaml up -d
```

There is no need to expose host block devices or use `--privileged`. If the appliance cannot start, inspect `docker compose logs forge` and run `docker compose exec forge libguestfs-test-tool`. [libguestfs troubleshooting](https://libguestfs.org/guestfs-faq.1.html)

## Development and verification

For API/UI development with Python 3.11 or later on Linux or macOS:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock
FORGE_DATA_DIR=./data .venv/bin/uvicorn forge.main:app --host 127.0.0.1 --port 8080
```

Actual image operations require Linux, the system image tools, and the matching `python3-guestfs` binding. A Linux development venv should be created with `--system-site-packages` to expose that binding. The Dockerfile lists the required Debian packages.

API documentation is available at `/docs`. Run automated tests with:

```sh
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

These tests use mocked image tooling to verify application behavior without a VM. A separate smoke check exercises a real offline Linux image, writes a harmless cron comment into the output, verifies that edit, validates the artifact checksum, and confirms the source bytes are unchanged:

```sh
./scripts/smoke-image.sh /path/to/source.qcow2 /path/to/new-output-directory
```

Run that script in the project Python environment on Linux x86_64/ARM64 or inside the supplied container with a read-only source mount and a writable output location. The output directory must not already exist. This smoke check is separate from a guest boot test and a provider import/launch test.

For a fixture whose boot arrangement you already know, set `FORGE_EXPECT_BOOT_MODE=uefi`, `bios`, `dual`, or `unknown` when running the script. It checks the detected result against that explicit expectation and verifies the source checksum immediately after inspection. This assertion still does not boot the guest.

Set `FORGE_SMOKE_UEFI_MIGRATION=1` to exercise migration on a BIOS-only fixture with the required EFI tools already installed. This smoke mode keeps guest networking and package installation disabled, so use an eligible Debian/Ubuntu fixture; the RPM migration path requires an explicit package workflow. The script additionally checks the output's EFI fallback loader and retained BIOS detection. It still requires separate UEFI and legacy VM boot tests.

Unit tests use mocked image tooling. Container startup and a real Debian import/edit/export round trip have also been exercised on a Linux x86_64 Docker host. An Oracle Linux 9.8 UEFI/XFS/LVM fixture was rebuilt from a 12 GiB test disk to exactly 10 GB, reducing its root filesystem from 8 GiB to 7.5 GiB. File contents and archived metadata, filesystem identities, source preservation and export byte comparison passed. The rebuilt image reached a serial login prompt under KVM/OVMF with no network device and temporary disk writes; its checksum remained unchanged.

The same Oracle fixture completed VM-to-bare-metal preparation and a reverse conversion to a VirtIO VM profile without guest network access or package installation. Both outputs passed driver, initramfs and generated boot-configuration verification, and the input hashes remained unchanged.

A real Debian 12 ARM64 image also passed import, ARM64 UEFI detection, a file edit, direct ext4 disk/root growth and export on the x86 worker. Guest-command requests correctly failed before queueing. A native ARM64 Docker deployment subsequently passed appliance startup, import, guest service enablement, initramfs regeneration and export with UEFI/kernel preservation and download checksum verification. ARM firmware boot and cloud launch remain separate tests; see the [architecture validation record](docs/image-architectures.md#validation-record).

Ubuntu 26.04.1 ARM64 validation additionally covers native VM and experimental ARM bare-metal preparation, its current dracut/cloud-init layout, Zstandard initramfs and automatic normalization of installer mount aliases to verified filesystem UUIDs. The VM candidate reached a serial login prompt under ARM UEFI/TCG. See the [Ubuntu validation record](docs/image-architectures.md#ubuntu-26041-arm64) for preparation results and boot-test scope.

Storage rebuilds and machine preparation still require an appropriate firmware boot and destination launch test for each image and target; these checks do not certify cloud support or physical hardware compatibility.

## Relationship to the QCOW2 optimization record

The supplied Oracle Linux optimization record informed source preservation, isolated libguestfs access, optional sparsification, zlib QCOW2 output, and guest-visible byte comparison after conversion. Its XFS procedure is implemented as an explicitly selected, validated filesystem rebuild for supported layouts. It creates new filesystems and verifies restored contents; it never shrinks XFS by truncating a disk or logical volume.

The record also distinguishes virtual capacity, compressed file length, and allocated host blocks. The UI preserves that distinction: reducing virtual disk size is not the same as reducing transfer bytes, and a smaller exported disk does not guarantee a smaller provisioned cloud boot volume. See [architecture and validation notes](docs/architecture.md) for implementation details.
