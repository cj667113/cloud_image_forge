# OCI image compatibility

Reviewed against Oracle's public documentation and running source/clone hosts on **2026-10-28**.

OCI image compatibility has three parts: the software and boot layout inside the disk, the image's cloud capability schema, and the hardware/network/storage selected when an instance is launched. A QCOW2 conversion only changes the disk container. Declaring a capability does not install a driver or prove that an instance boots.

This document covers the 13-key global image capability schema shown in Oracle's current overview, plus the corresponding image-import and instance-launch fields. Forge's reference catalog additionally exposes `ACCELERATEDPV` from the current launch API; it is not a downloaded regional schema. Account resources such as compartments, subnets, shapes, encryption keys, and IAM policies remain cloud configuration. Cloud Image Forge generates an image and configuration handoff; it does not create those resources.

## Cloud Image Forge workflow

Open the **OCI compatibility** step for an inspected image, enable OCI preparation, and select the allowed and preferred capability values. The preview reports planned guest changes, blockers, warnings, and coverage for every selected key. Eligible BIOS images can explicitly add UEFI support through the **Boot & kernel** step's migration option. The build repeats validation against the resulting disk before publishing its artifact. An unsupported migration or missing mandatory guest prerequisite is a blocker; a cloud configuration requirement remains a clearly reported follow-up.

The recipe's optional `oci` object contains:

| Recipe field | Purpose |
| --- | --- |
| `capabilities` | Exact OCI key mapped to `default_value` and, for enums, `values` |
| `guest` | Enable preparation, optional package installation, networking/cloud-init/serial configuration, and IPv6 validation acknowledgement |
| `import_options` | Image metadata, object location, tags, and shape compatibility bounds |
| `global_schema_version` | Version name obtained from the destination region |
| `global_schema` | Optional downloaded schema; accepts CLI or REST key naming |

Omitted capability settings inherit the selected schema's defaults. Defaults still undergo guest-readiness checks. A newly supplied schema can expose additional capability keys or values, but additional keys without a guest adapter are exported with a warning and require separate validation. Loading a schema is not a live OCI account connection.

Successful OCI builds provide an **OCI configuration** download at `/api/artifacts/{id}/oci-bundle`:

| ZIP member | Intended use |
| --- | --- |
| `image-import.json` | CLI input for `compute image import from-object` or `from-object-uri` |
| `image-capability-schema.json` | CLI input for creating the imported image's capability schema |
| `schema-data.json` | Capability map for schema creation/update |
| `instance-launch-options.json` | Optional `--launch-options` fragment for a later instance launch |
| `instance-launch-fragment.json` | Partial instance request containing launch options and top-level PV encryption selection; merge into a complete launch request |
| `shape-001.json`, ... | Selected image-shape compatibility entries, when provided |
| `forge-oci-profile.json` | The selected Forge OCI configuration |
| `artifact.json` | Exported image identity and checksum details |
| `README.txt` | Commands, placeholders, and cloud-validation steps |

This ZIP contains configuration only. Download/upload the QCOW2 separately; the ZIP is not an OCI `.oci` image archive. No OCI command is executed by generating or downloading it. Replace every `REPLACE_*` placeholder, validate against the region's live schema, and follow the included instructions. A presigned object URI supplied in the form is included in the import JSON/profile and must be kept private.

## Published global capability keys

The following are the exact case-sensitive keys and published values. The **global default** column records Oracle's documented schema default; it is not evidence that an imported guest supports that value. Always check the live schema version in the destination region before applying a custom schema. [Oracle global image capability schema](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/configuringimagecapabilities.htm)

| Capability key | Descriptor | Published values | Global default |
| --- | --- | --- | --- |
| `Compute.AMD_SecureEncryptedVirtualization` | `boolean` | `false`, `true` | `false` |
| `Compute.Firmware` | `enumstring` | `BIOS`, `UEFI_64` | `UEFI_64` |
| `Compute.SecureBoot` | `boolean` | `false`, `true` | `false` |
| `Compute.LaunchMode` | `enumstring` | `NATIVE`, `EMULATED`, `PARAVIRTUALIZED`, `CUSTOM` | `PARAVIRTUALIZED` |
| `Network.AttachmentType` | `enumstring` | `E1000`, `VFIO`, `PARAVIRTUALIZED` | `PARAVIRTUALIZED` |
| `Network.IPv6Only` | `boolean` | `false`, `true` | `false` |
| `Storage.BootVolumeType` | `enumstring` | `ISCSI`, `SCSI`, `IDE`, `PARAVIRTUALIZED` | `PARAVIRTUALIZED` |
| `Storage.LocalDataVolumeType` | `enumstring` | `ISCSI`, `SCSI`, `IDE`, `PARAVIRTUALIZED` | `PARAVIRTUALIZED` |
| `Storage.RemoteDataVolumeType` | `enumstring` | `ISCSI`, `SCSI`, `IDE`, `PARAVIRTUALIZED` | `PARAVIRTUALIZED` |
| `Storage.ConsistentVolumeNaming` | `boolean` | `false`, `true` | `true` |
| `Storage.ParaVirtualization.EncryptionInTransit` | `boolean` | `false`, `true` | `true` |
| `Storage.ParaVirtualization.AttachmentVersion` | `enuminteger` | `1`, `2` | `2` |
| `Storage.Iscsi.MultipathDeviceSupported` | `boolean` | `false`, `true` | `false` |

**Custom images do not support Secure Boot**, even though the global schema contains that key. IPv6-only capability requires a validated IPv6-only guest; iSCSI boot and remote-volume attachments are incompatible with Customer VMI IPv6-only launches. The capability does not create or configure an IPv6 VCN, subnet, or VNIC. [Oracle capability restrictions](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/configuringimagecapabilities.htm)

Oracle's current SDK and CLI expose some newer launch values that are absent from that overview: `ACCELERATEDPV` networking/launch mode and `VFIO`/`NVME` storage values. Forge adds `ACCELERATEDPV` to its reference catalog for both `Compute.LaunchMode` and `Network.AttachmentType`. Their presence in the SDK does not make them valid in every image capability schema version. A generated schema must be a subset of the values in the region's selected global schema. Loading a regional schema replaces the reference choices; Forge does not inject unsupported values into it. The storage defaults remain unchanged: the reviewed Ax VM uses VirtIO SCSI, not NVMe. [Current LaunchOptions model](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/core/models/oci.core.models.LaunchOptions.html), [current image-import command](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/compute/image/import/from-object.html)

## Reviewed E6 Ax VM and E5 bare-metal configurations

Read-only SSH inspection of user-provided hosts established the following configurations. These are observations of those running instances, not a minimum-kernel specification or certification of a rebuilt image.

| Property | `VM.Standard.E6.Ax.Flex` | `BM.Standard.E5.192` |
| --- | --- | --- |
| Guest | Oracle Linux 9.8, x86_64, UEK `6.12.0-207.111.5.1.el9uek.x86_64` | Same |
| Boot | UEFI, GPT; no Secure Boot enabled | UEFI, GPT; Secure Boot disabled |
| Primary NIC | `virtio_net` over `virtio_pci`; PCI `1af4:1041`, Oracle subsystem `108e:1200` | ConnectX-6 Dx physical NICs, `mlx5_core`; PCI `15b3:101d` |
| Boot storage | VirtIO SCSI, PCI `1af4:1048`; no active iSCSI session | iSCSI BlockVolume, active `iscsi_tcp` session and firmware iBFT |
| Layout | 46.6 GiB disk; 100 MiB ESP, 2 GiB XFS `/boot`, LVM with XFS root and `/var/oled` | Same layout |
| Portable initramfs | OCI vendor configuration sets `hostonly="no"` | Same; includes firmware iSCSI discovery, network userspace, `mlx5_core`, `iscsi_ibft`, and `iscsi_tcp` |

`ACCELERATEDPV` uses the Acceleron SmartNIC data plane to offload network processing from the host CPU. Oracle lists it as the only networking type for E6 Ax VMs. Inside the inspected Linux guest it still uses VirtIO network drivers, so loading an unrelated physical-NIC driver is not the adaptation. The cloud launch must select AcceleratedPV on a supporting shape with a compatible image. Oracle currently lists Oracle Linux 8/9/10 platform images for this networking type; the host audit does not extend that support statement to arbitrary custom images. [Networking types and supported images](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/edit-launch-options.htm)

To prepare an E6 Ax candidate, select **Accelerated PV** for the preferred network attachment and launch mode, use PV boot storage, retain working UEFI, and set the import launch mode to Accelerated PV. Add `VM.Standard.E6.Ax.Flex` to the shape entries. **Destination → Hardware compatibility** offers Accelerated PV networking with either preservation or reconfiguration. The planner checks VirtIO drivers across every selected kernel; reconfiguration rebuilds initramfs when needed, while preservation verifies the existing archive. It does not enable hardware offload on an ordinary PV shape.

For the reviewed E5 bare-metal target, use **VM → Bare metal**, iSCSI boot, hardware/VFIO networking, and the `mlx5_core` NIC driver. Keep UEFI and allow iSCSI/VFIO in the OCI capabilities. When `BM.Standard.E5.192` is a shape entry, validation requires that actual driver instead of accepting an unrelated installed VF driver. In this context VFIO is OCI's launch setting; the physical Linux NIC is bound to `mlx5_core`, not `vfio-pci`. The existing preparation workflow requires firmware iSCSI discovery and complete early networking in the initramfs. It preserves the observed numeric `node.session.timeo.replacement_timeout` policy while removing machine-specific targets and identities during migration. It does not copy live host addresses, IQNs, or credentials.

The platform images contain firmware-iSCSI arguments even on the running PV VM; those arguments alone do not prove that a guest actually booted over iSCSI. Transport selection must also use storage and firmware evidence. Forge's **Reconfigure** VM path removes iSCSI boot dependencies; its bare-metal path prepares them. **Preserve & validate** can retain verified optional discovery. The shared filesystem layout is already covered by the supported XFS/LVM rebuild workflow, subject to each imported image's own inspection and sizing checks.

Oracle publishes [engineering guidance for preparing external images for VM and bare-metal boot](https://blogs.oracle.com/cloud-infrastructure/enabling-external-custom-images-virtual-and-bare-metal), while its [BYOI reference still excludes bare-metal support](https://docs.oracle.com/en-us/iaas/Content/Compute/References/bringyourownimage.htm). Forge therefore retains the experimental designation for bare-metal preparation. These audits did not import, launch, or reboot a Forge-built image on either new machine; destination boot validation remains outstanding.

### VM3 native-image portability

A subsequent read-only audit examined an OCI `VM.Standard.E5.Flex` created directly from a custom image captured from the reviewed bare-metal instance. The image had not passed through Forge. Its kernel, initramfs and `/etc/default/grub` were byte-identical to those on the bare-metal source by SHA-256 comparison. The OCI dracut configuration also matched and set `hostonly="no"`.

The VM used `virtio_net` and VirtIO SCSI, while preserving the same LVM/XFS root. It had no firmware iBFT table and no active iSCSI session. Its command line still contained `netroot=iscsi` and `rd.iscsi.firmware=1`. The boot log showed unsuccessful iSCSI discovery, followed by successful local-root discovery and mounting. The actual archived systemd dracut hook permits completion when `initrd-root-device.target` is active; it does not require an iSCSI session after that local root is found.

Oracle cloud-init completed first-boot provisioning and wrote a DHCP profile for the new VM NIC. The old bare-metal NIC profile remained unused. `fstab` retained its root, boot and EFI references; its only difference was a duplicate `/.swapfile` entry. These observations establish portability of this OCI-native image on the tested VM, not that arbitrary bare-metal images boot after iSCSI failure or that a Forge export has been tested.

Forge now offers **Preserve & validate** to check existing prerequisites without rewriting hardware configuration. **Reconfigure** remains available when adaptation is required. The preserve assessment distinguishes optional firmware discovery from mandatory network-root requirements and treats unreadable or unsupported evidence as unknown. See [preservation behavior and boot logic](storage-and-platform.md#optional-firmware-discovery-and-local-root-discovery).

Native OCI custom-image capture is distinct from importing an external BYOI image onto bare metal. OCI custom images inherit compatible shapes from their base image; the service launch configuration still determines the exposed devices. [OCI custom-image behavior](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/managingcustomimages.htm)

### E6 Ax to E5 Flex native-image portability

A separate read-only comparison examined a `VM.Standard.E5.Flex` launched directly from the reviewed `VM.Standard.E6.Ax.Flex` instance's custom image, without Forge processing. SSH and the running root filesystem confirmed the clone was operational. IMDS confirmed both shape names. The individual launch-mode and launch-options metadata endpoints were unavailable, so this audit does not claim to have retrieved the instances' control-plane `networkType` fields or the custom image's capability schema.

| Observed property | E6 Ax source | E5 Flex clone |
| --- | --- | --- |
| Linux NIC driver | `virtio_net` over `virtio-pci` | Same |
| NIC PCI device | Modern VirtIO `1af4:1041`, address `00:05.0` | Same |
| NIC subsystem | Oracle `108e:1200` | Oracle `108e:1100` |
| NIC name | `enp0s5` | Same |
| Boot controller | VirtIO SCSI `1af4:1048`, subsystem `108e:1100` | Same |
| Kernel | UEK `6.12.0-207.111.5.1.el9uek.x86_64` | Same version and SHA-256 |
| Initramfs and boot configuration | Existing OCI image configuration | Identical initramfs, GRUB defaults/generated menu, BLS and kernel-command-line hashes |
| Root and firmware | UEFI, local XFS/LVM root; no iBFT or iSCSI sessions | Same |
| Network identity | Source NIC MAC and generated DHCP profile | New MAC; generated DHCP profile matches the destination NIC |

Oracle documents **AcceleratedPV** as the only E6 Ax networking type and **Paravirtualized/SR-IOV** for E5 Flex. The E5 guest's observed VirtIO NIC is consistent with the PV path. Acceleron describes the infrastructure providing the Ax data plane; it does not imply a separate Linux driver named Acceleron. Both observed devices bind to the existing VirtIO driver stack. The different subsystem IDs alone do not call for replacing that driver or rebuilding the initramfs. [Shape networking types](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/edit-launch-options.htm)

Cloud-init completed on both machines, and their cached instance identities matched their respective IMDS identities. The clone's cloud-init-generated `ifcfg-enp0s5` uses DHCP, is enabled at boot, and matches the clone's new MAC. Cloud configuration and dracut configuration hashes matched the source. The existing narrow Oracle bootstrap validator reported ready for both guests; no additional network-rewrite adapter was needed for this evidence.

The clone also has a second identical `/.swapfile none swap sw 0 0` entry in `fstab`, as observed in the earlier bare-metal-to-VM clone. Preserve mode already retains and warns about identical duplicate swap entries; it does not treat that duplication alone as a boot blocker or silently remove it.

This move retains PV storage at both ends. Its portability is supported by the existing shared drivers, stable root identity and working first-boot networking. The retained iSCSI discovery arguments are a separate optional path; an iSCSI failure is not what converts AcceleratedPV networking to ordinary PV. The running clone establishes this native capture's behavior in the tested direction, without certifying every custom image or a Forge-built export.

In Forge, use **Preserve & validate → Virtual machine → Virtual machine**, PV boot, and the destination's network attachment. For the E5 target select **Paravirtualized**; for an E6 Ax target select **Accelerated PV**. Keep OCI guest preparation at **Validate only** to retain existing hardware configuration. A source image's origin and PCI subsystem ID do not select the destination attachment automatically.

An image intended for both destinations can advertise both network values when its guest and regional capability schema support them. Forge checks that each known shape has a supported allowed network choice. An AcceleratedPV-only image cannot advertise E5/E6 non-Ax support, and a PV-only image cannot advertise Ax support. When a portable image's preferred settings do not match an advertised shape, its generated default launch fragment needs destination-specific review. `LaunchOptions.networkType` can override network defaults; `launchMode` is not a top-level `LaunchInstanceDetails` field. [Launch options](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/core/models/oci.core.models.LaunchOptions.html), [instance launch fields](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/core/models/oci.core.models.LaunchInstanceDetails.html)

## Supported values and preferred values

An enum descriptor's `values` array declares supported choices. Its `defaultValue` chooses the preferred member of that array. The API has no `preferredValue` property. Setting `source` to `IMAGE` makes the entry an image-specific setting. Booleans use JSON `true`/`false`, not quoted strings. [Enum descriptor model](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/core/models/oci.core.models.EnumStringImageCapabilitySchemaDescriptor.html), [boolean descriptor model](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/core/models/oci.core.models.BooleanImageCapabilitySchemaDescriptor.html)

For example, this schema fragment permits only UEFI firmware and makes it preferred:

```json
{
  "Compute.Firmware": {
    "descriptorType": "enumstring",
    "source": "IMAGE",
    "values": ["UEFI_64"],
    "defaultValue": "UEFI_64"
  },
  "Compute.SecureBoot": {
    "descriptorType": "boolean",
    "source": "IMAGE",
    "defaultValue": false
  }
}
```

Do not advertise both firmware modes unless the disk has a working boot chain for each. Supporting both x86_64 and Arm is not a schema switch: the guest kernel, userspace binaries, and bootloader must match the target architecture. These are engineering constraints on this application's output, independent of the number of options OCI exposes.

## Guest preparation versus cloud settings

The following mapping identifies what a preparation engine can check or change, and what must still be selected or verified in OCI. It is an implementation boundary, not a claim that every possible guest/shape combination has been tested.

| Selection | Guest-side work | Cloud-side requirement |
| --- | --- | --- |
| Firmware | Inspect existing boot paths; optionally migrate an eligible BIOS image by adding an EFI fallback while preserving BIOS structures | Set the firmware capability and use matching launch firmware |
| Launch mode | Prepare drivers for the chosen network and storage configuration | Set import mode and capability values; verify effective launch options |
| NIC attachment | Check/install the relevant NIC driver and include it in initramfs when early networking needs it | Use a compatible VNIC type and shape |
| Boot/local/remote storage | Check the controller/transport drivers; prepare initramfs; keep valid UUID-based mounts | Use compatible volume attachment types |
| Consistent volume naming | Verify that the guest actually provides OCI device-name support | Enable the image capability and choose a device path when attaching volumes |
| IPv6-only | Prepare the guest network stack, DHCP/RA handling, and provisioning path; validate a real launch | Use an IPv6-only-compatible network and VNIC configuration |
| PV encryption in transit | Preserve compatible PV drivers | Enable the applicable cloud capability/attachment encryption option |
| PV attachment version | Preserve compatible PV drivers | Select a schema-supported version on compatible infrastructure |
| iSCSI multipath | Verify supported Oracle Linux/UEK guest and multipath tooling/configuration | Use a supported shape, volume performance tier, and attachment configuration |
| AMD SEV | Verify supported kernel/guest prerequisites | Select a supported confidential-computing shape, OS, region, and launch platform configuration |
| Secure Boot | Preserve existing EFI boot files where appropriate | Keep disabled for OCI custom images |

Consistent OCI names such as `/dev/oracleoci/oraclevda` are a distinct feature from filesystem UUIDs. A stable `UUID=` entry in `fstab` alone does not establish consistent-volume-naming support. [Consistent device paths](https://docs.oracle.com/en-us/iaas/Content/Block/References/consistentdevicepaths.htm)

For custom images, Oracle documents iSCSI multipath support with Oracle Linux-derived images using UEK6U1 or later, beginning at kernel release `5.4.17-2036`; shape and attachment requirements also apply. Installing `multipath-tools` on an arbitrary distribution is not enough to declare that OCI capability. [Multipath prerequisites](https://docs.oracle.com/en-us/iaas/Content/Block/Tasks/configuringmultipathattachments.htm), [custom-image troubleshooting](https://docs.oracle.com/en-us/iaas/Content/Block/Tasks/troubleshootingmultipathattachments.htm)

AMD memory encryption is established by the launched platform. Oracle publishes an OS/shape/region support matrix and requires confidential computing to be selected at launch. Offline disk editing cannot prove memory confidentiality or attestation. [Confidential computing](https://docs.oracle.com/en-us/iaas/Content/Compute/References/confidential_compute.htm)

## Launch-mode presets

The documented mode descriptions establish these associations:

| Mode | Documented association |
| --- | --- |
| `NATIVE` | iSCSI boot and VFIO devices |
| `EMULATED` | Emulated devices, including E1000 networking and an emulated disk controller |
| `PARAVIRTUALIZED` | VirtIO devices |
| `CUSTOM` | Explicit launch compatibility options |
| `ACCELERATEDPV` | Accelerated paravirtualized networking; verify live schema support |

Firmware should be selected from the guest's actual boot capabilities. The mode name alone does not justify converting its partition layout or switching its firmware. Oracle's emulated-to-PV migration example retains BIOS while changing network and storage choices to PV. [CreateImageDetails mode descriptions](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/core/models/oci.core.models.CreateImageDetails.html), [BYOI migration guidance](https://docs.oracle.com/en-us/iaas/Content/Compute/References/bringyourownimage.htm)

Oracle recommends Native at import for standalone QCOW2 files exported from OCI. This import recommendation does not reproduce a separate `image_metadata.json` file's firmware and attachment selections; inspect the imported image and apply its intended capability schema. [OCI import workflow](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/custom-images-import.htm)

## Import JSON, capability JSON, and instance launch JSON

These are separate requests. The `compute image create --image-source-details` import path is deprecated in the current CLI; use `compute image import from-object` or `from-object-uri`. [CLI deprecation](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/compute/image/create.html)

For **`oci compute image import from-object --from-json`**, the required CLI JSON keys are `compartmentId`, `bucketName`, `name`, and `namespace`. Optional image-specific keys are `displayName`, `launchMode`, `operatingSystem`, `operatingSystemVersion`, `sourceImageType`, `definedTags`, and `freeformTags`. `name` is the object key, not the image display name. The URI variant replaces `bucketName`/`name`/`namespace` with `uri`. [Object import parameters](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/compute/image/import/from-object.html), [URI import parameters](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/compute/image/import/from-object-uri.html)

Neither image-import command accepts `launchOptions`. Image update accepts display name, OS metadata, and tags; use an image capability schema for detailed image compatibility settings. [Image update parameters](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/compute/image/update.html)

For **`oci compute image-capability-schema create --from-json`**, use:

```json
{
  "compartmentId": "REPLACE_WITH_COMPARTMENT_OCID",
  "imageId": "REPLACE_WITH_IMPORTED_IMAGE_OCID",
  "globalImageCapabilitySchemaVersionName": "REPLACE_WITH_REGION_SCHEMA_VERSION",
  "schemaData": {}
}
```

Replace `schemaData` with the validated image capability map. Optional fields are `displayName`, `definedTags`, and `freeformTags`. The **REST API** uses `computeGlobalImageCapabilitySchemaVersionName` instead of the shorter **CLI input** key `globalImageCapabilitySchemaVersionName`. Do not interchange the two JSON documents. [CLI schema create](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/compute/image-capability-schema/create.html), [REST field names](https://docs.oracle.com/en-us/iaas/tools/dotnet/latest/api/Oci.CoreService.Models.CreateComputeImageCapabilitySchemaDetails.html)

An **instance launch** can include a `launchOptions` object. Its relevant fields are `firmware`, `networkType`, `bootVolumeType`, `remoteDataVolumeType`, `isConsistentVolumeNamingEnabled`, and `isEncryptionInTransitEnabled`. The older nested `isPvEncryptionInTransitEnabled` is deprecated in the current SDK. There is no `localDataVolumeType` field in the current `LaunchOptions` model; the image capability remains `Storage.LocalDataVolumeType`. [LaunchOptions API model](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/core/models/oci.core.models.LaunchOptions.html)

The instance launch command separately exposes top-level `--is-pv-encryption-in-transit-enabled` / `isPvEncryptionInTransitEnabled`, covering paravirtualized boot and block volume attachments. It is not an image import flag and is not the same location as the deprecated nested field. [Instance launch command](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/compute/instance/launch.html), [LaunchInstanceDetails model](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/core/models/oci.core.models.LaunchInstanceDetails.html)

`instance-launch-fragment.json` includes this top-level encryption selection alongside `launchOptions`. It is intentionally incomplete: the operator still supplies the instance's image/source, shape, compartment, availability domain, and network configuration. A normal `LaunchInstanceDetails` request does not have a `launchMode` field; that mode is part of the imported image and its capability configuration. The separate instance-configuration model does expose a launch mode, so its request shape must not be confused with direct instance launch.

Memory encryption and Secure Boot are instance `platformConfig` properties, respectively `isMemoryEncryptionEnabled` and `isSecureBootEnabled`, with a platform type appropriate to the selected shape. They are not ordinary guest kernel parameters. An image-capability declaration still has to satisfy the custom-image restrictions above. [Platform configuration model](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/core/models/oci.core.models.PlatformConfig.html)

### Shape compatibility and service-owned image fields

An image's supported-shape list is a separate control-plane resource. `oci compute image-shape-compatibility-entry add` accepts CLI JSON fields `imageId`, `shapeName`, and optional `memoryConstraints`/`ocpuConstraints`. The memory object uses integer `minInGBs`/`maxInGBs`; the OCPU object uses integer `min`/`max`. These describe tested bounds for an image and shape; they do not resize the guest disk, translate machine code, or manufacture missing CPU/device support. [Shape compatibility command](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/compute/image-shape-compatibility-entry/add.html), [memory constraints](https://docs.oracle.com/en-us/iaas/tools/dotnet/latest/api/Oci.CoreService.Models.ImageMemoryConstraints.html), [OCPU constraints](https://docs.oracle.com/en-us/iaas/tools/dotnet/latest/api/Oci.CoreService.Models.ImageOcpuConstraints.html)

The `Image` response also contains service-owned fields such as its OCID, lifecycle state, creation time, billing size, boot-volume size, and image-creation eligibility. These are not editable import options simply because they appear in exported metadata or API responses. In particular, `sizeInMBs` describes the boot volume's size and differs from the uploaded QCOW2 file length. [Image resource model](https://docs.oracle.com/en-us/iaas/tools/python/latest/api/core/models/oci.core.models.Image.html)

## Verify the region schema and apply a reviewed configuration

The following commands are instructions for the operator. Cloud Image Forge does not execute them or contact an OCI tenancy during a build. Replace all placeholder values and review the generated files first.

Retrieve the current schema identifiers:

```sh
oci compute global-image-capability-schema list --all
```

Use that result's `id` and `current-version-name`:

```sh
oci compute global-image-capability-schema-version get \
  --global-image-capability-schema-id GLOBAL_SCHEMA_OCID \
  --global-image-capability-schema-version-name VERSION_NAME
```

Compare the selected keys, descriptor types, allowed values, and defaults to that region's schema. Query existing image-specific schemas before creating one:

```sh
oci compute image-capability-schema list --image-id IMPORTED_IMAGE_OCID --all
```

If none exists, create one with the reviewed CLI JSON. If one already exists, review its existing entries and update it deliberately; do not silently discard unrelated settings. The update command supports `--if-match` for an ETag-based concurrency check. [Capability-schema workflow](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/configuringimagecapabilities-tasks.htm), [schema update parameters](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/cmdref/compute/image-capability-schema/update.html)

After import and schema application, inspect the image's effective firmware and launch options, then boot it on the intended OCI shape/network configuration. Successful offline driver checks, `qemu-img check`, and byte comparisons do not replace that final validation.
