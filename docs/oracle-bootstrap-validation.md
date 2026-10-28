# Oracle cloud-init bootstrap validation

Preserve-and-validate can recognize the Oracle network bootstrap profile audited
on **2026-10-28: Oracle Linux 9.8 with cloud-init 24.4-8.0.1.el9_8.1**. The audit
observed a captured bare-metal image booting as a VM with unchanged kernel,
initramfs and GRUB defaults. Oracle cloud-init rendered DHCP configuration for
the destination NIC during normal first-boot initialization.

The offline helper checks the reviewed Oracle datasource, DHCP and cache-policy
source fingerprints, cloud-init units, installed DHCP tools, configuration
precedence, cache-trust markers and network overrides. It reads guest files
without running guest code, executing scripts, loading cached Python objects or
reading user-data. Existing MAC-bound profiles are accepted only within this
reviewed bootstrap path; package or driver presence alone is insufficient.

This profile is intentionally narrow. Different source/unit fingerprints and
unsupported configuration syntax return **unknown**, requiring review. Disabled
cloud-init/networking, missing prerequisites and trusted stale cache markers
prevent readiness. No packages are installed or guest configuration rewritten
by this assessment.

The bootstrap result is one part of portability validation. It does not verify
destination metadata reachability, DHCP service, OCI image eligibility or a
successful boot. Firmware, root discovery and initramfs checks remain separate.
Bare-metal image preparation retains its experimental provider limitation.

Cloud-init normally compares the cached instance identity with the destination
identity and can rerun per-instance setup without clearing its cache. Trusting
the cache changes that behavior. See the official [first-boot explanation](https://docs.cloud-init.io/en/latest/explanation/first_boot.html).
System and kernel network settings can override datasource networking; see
[network configuration](https://docs.cloud-init.io/en/latest/reference/network-config.html).
The Oracle datasource's `configure_secondary_nics` setting concerns additional
NICs and does not disable primary NIC bootstrap; see the [Oracle datasource](https://docs.cloud-init.io/en/latest/reference/datasources/oracle.html).
