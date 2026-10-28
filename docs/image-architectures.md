# Image CPU architectures

Forge supports single-disk **x86_64** and **ARM64 (`aarch64`) Linux images**. It normalizes `amd64` and `arm64` aliases. The source architecture comes from libguestfs inspection and remains unchanged in the exported image and artifact manifest. Changing an OCI shape, image format or boot setting does not translate the kernel and installed software to another CPU instruction set. 32-bit x86/ARM guests remain unsupported.

## Image operations and workers

| Operation | Worker requirement |
| --- | --- |
| Import, OS/boot/filesystem inspection, systemd exploration | Either supported worker architecture |
| Edit cron, fstab, custom service files, module configuration | Either; these are data-only file edits |
| Direct supported partition/LV resizing; supported GPT/UEFI filesystem rebuild | Either; uses appliance-native filesystem tools |
| Preserve & validate; OCI validate-only | Either; actual guest prerequisites must pass |
| Sparsify, convert, compare and export | Either |
| Install/remove packages; enable/disable/mask/unmask services | Same architecture as the guest |
| Disable SSH password login; add authorized keys; create users with keys | Same architecture as the guest; verifies guest OpenSSH configuration |
| Select default kernel; change kernel arguments or `/etc/default/grub`; regenerate GRUB/initramfs | Same architecture as the guest |
| Reconfigure hardware or prepare the OCI guest | Same architecture as the guest |
| BIOS-to-UEFI conversion | Eligible x86_64 guest on an x86_64 worker only |

The distinction follows libguestfs's execution model: appliance filesystem tools can manipulate another architecture's disk, while guest commands execute that guest's binaries. Installing a QEMU user emulator in the API container alone does not provide an emulator inside the separate appliance. Forge does not assume or automatically register cross-architecture command execution. [Libguestfs architecture support](https://libguestfs.org/virt-builder.1.html#architecture)

The current worker is checked when a preview/build is requested and again before guest-changing preparation. Cached inspection data cannot override that decision. The UI shows a compact worker notice and retains the user's draft; unsupported commands produce an actionable error before a build job is created. `/api/health` reports `worker_arch`, `guest_architectures` and `guest_execution_architectures`. An inspection's `execution` field is informational and can become stale when moved between workers.

File-only edits on a different-architecture worker use the read/write appliance directly. For enabled SELinux guests, the appliance relabels edited paths using the guest's inspected policy data. Missing, ambiguous or unsupported policy information blocks the edit rather than invoking guest code. Native-worker edits retain the existing `virt-customize` relabeling path.

## Docker deployment

The same Dockerfile builds natively on Linux `amd64` or `arm64`: x86 uses `qemu-system-x86` and `linux-image-amd64`; ARM uses `qemu-system-arm` and `linux-image-arm64`. Compose no longer forces an amd64 container. Run the normal `docker compose up --build -d` command on the matching Linux host for guest-program operations. Both workers can perform the data-only operations above for either guest architecture.

Use separate deployments and separate data volumes if you need both worker architectures. There is no automatic remote-worker routing or shared distributed queue. Transfer a source through local download/upload or the configured object store when moving it to another worker. Never run two workers against the same writable data directory. KVM accelerates the worker's appliance when the host supports it; it does not make foreign guest binaries executable.

For a remote ARM VM without `/dev/kvm`, keep the default `force_tcg` setting and start Compose without the KVM override. The container and appliance still run ARM64; software emulation makes image operations slower. Check `/api/health` for `worker_arch: "aarch64"`, then run `docker compose exec forge libguestfs-test-tool` to verify that the appliance actually launches. API health alone checks tool availability.

To use the loopback-bound UI over SSH, forward a separate local port for each worker:

```sh
ssh -i /path/to/private-key -N -L 127.0.0.1:18081:127.0.0.1:8080 opc@arm-worker
```

Open `http://127.0.0.1:18081` and enter that deployment's `API_TOKEN`. If another worker uses `localhost`, using `127.0.0.1` here also separates their browser session cookies, which are not isolated by port. Keep the SSH connection open. Set a different random token on each deployment, keep its `.env` private, and allow storage for uploaded sources, working disks and exports. A large cloud boot volume can still have a small root filesystem; inspect filesystem free space before importing large images.

## Boot and hardware validation

EFI detection validates the PE machine type and matches it to the inspected guest. x86 fallback is `EFI/BOOT/BOOTX64.EFI`; ARM64 fallback is `EFI/BOOT/BOOTAA64.EFI`. A valid loader for the wrong architecture does not establish a boot chain. ARM64 plans require current architecture-aware UEFI evidence and kernel configuration proving `CONFIG_ARM64`, `CONFIG_EFI` and `CONFIG_EFI_STUB`. Old imports need refreshed inspection. The unchanged EFI partition and source architecture are checked after a filesystem rebuild.

The initial ARM64 hardware profiles cover **VMs with PV boot and PV or AcceleratedPV networking**. Required drivers are checked per kernel; missing evidence remains unknown or blocked. ARM64 BIOS migration, physical/VFIO networking and bare-metal firmware-iSCSI preparation remain unsupported. An already-valid ARM64 UEFI image can satisfy an explicitly requested UEFI migration as a no-op without executing guest tools.

ARM serial preparation uses `ttyAMA0` and requires built-in PL011 console support; x86 retains `ttyS0`. A successful offline check does not verify destination firmware, metadata/DHCP availability or a cloud boot. [Oracle serial console configuration](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/enablingserialconsoleaccess.htm), [Linux EFI stub](https://docs.kernel.org/admin-guide/efi-stub.html)

## OCI targets

Known Arm shapes, including `VM.Standard.A1.Flex`, `A2.Flex`, `A4.Flex` and `A4.Ax.Flex`, require an ARM64 image. Known Intel/AMD shapes require x86_64. Forge rejects incompatible image/shape pairs in both directions. An unknown future shape remains subject to explicit destination validation; a familiar-looking name is insufficient evidence. AcceleratedPV also requires a supporting Ax shape, compatible image and regional capability schema. Selecting a shape does not establish bare-metal preparation support. [OCI shape architectures](https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm)

The Oracle cloud-init bootstrap preservation profile remains deliberately narrow. ARM support does not automatically extend that profile to unreviewed implementations; portable DHCP or independently verified provisioning evidence is still required.

## Validation record

On 2026-10-28, an official Debian 12 genericcloud ARM64 QCOW2, verified against Debian's published SHA-512 checksum, passed 27 runtime checks in an isolated x86_64 Docker worker. The API imported it and detected ARM64 UEFI, rejected guest-command requests without queueing jobs, edited an inert cron file, grew the ext4 root/disk from 3 GiB to 4 GiB, and exported QCOW2. Independent reinspection, file readback and download hashing passed; original and imported source fingerprints were unchanged. The fixture's nonconsecutive partition numbering remained outside the existing filesystem-rebuild profile, so the runtime resize used direct growth.

A separate native ARM64 deployment on Oracle Linux 9.8 passed 46 runtime checks the same day with the default direct/TCG backend and no `/dev/kvm`. The unprivileged container launched an ARM64 libguestfs appliance using `qemu-system-aarch64`. Through the API, it imported a checksum-verified Debian 12 ARM64 image, enabled a harmless custom service using the guest's `systemctl`, rebuilt its initramfs, and exported QCOW2. Independent inspection confirmed the enabled service and new configuration marker inside the rebuilt initramfs; the kernel binary and entire EFI partition retained their SHA-256 hashes. The downloaded artifact matched its manifest checksum, and both original fixtures and imported sources were unchanged. A Debian x86_64 image could be imported and inspected, while service and initramfs requests were rejected before queueing. Browser checks covered login, ARM detection, wizard navigation, ARM shape settings and responsive layout.

These tests exercise offline image operations. An ARM firmware boot and destination cloud launch were not performed. `scripts/smoke-image.sh` accepts either supported Linux worker and verifies that exported images retain the source architecture.
