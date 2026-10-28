# SSH access in exported images

The **Access** wizard step is optional. Leaving it unchanged preserves the image's SSH configuration and accounts. All requested changes apply to the disposable working image; the imported source and the Forge server's own SSH access are unchanged.

## Choose the access changes

- **Disable SSH password login** disables both password and keyboard-interactive authentication. It can be selected independently of key uploads when the image already has suitable keys or the cloud provider will provision them.
- **Add user keys** appends public keys to an existing local account. Select an inspected username or enter one manually. Refresh inspection to populate the account list for an older import.
- **Create this user** creates a local account with a home directory, an unusable password and no added administrator privileges. It requires an unused username and at least one public key.

Paste one OpenSSH public key per line or select `.pub` files. Supported keys are Ed25519, RSA of 2048–8192 bits, and ECDSA using NIST P-256/P-384/P-521. Private keys, certificates, and newly supplied `authorized_keys` options are rejected. Existing key lines and their restrictions are retained; duplicate key material is not appended again. Each recipe allows up to 16 users and 32 keys per user. Review shows key counts and SHA-256 fingerprints rather than full key material.

Keep a working key or provider provisioning path before disabling password login. Forge does not change existing account passwords, grant sudo access, enable root login, or configure cloud metadata keys. A new account's key is included in the exported image, so instances created from it inherit that authorized key.

## Application and verification

SSH changes require a worker matching the guest architecture because they use the guest's account and OpenSSH tools. Missing tools or unsupported account/configuration layouts produce an error. Data-only inspection remains available on either supported worker architecture.

OpenSSH normally takes the first value it encounters, while conditional `Match` sections can select different authentication settings. Forge checks the loaded configuration and applies the requested password policy across supported includes and conditional sections, then validates it using the guest's `sshd`. Disabling only `PasswordAuthentication` is insufficient when PAM can accept a password through keyboard-interactive authentication. [OpenSSH configuration](https://man.openbsd.org/sshd_config), [cloud-init password configuration](https://docs.cloud-init.io/en/latest/reference/modules.html#set-passwords)

Authorized keys are written with the account's ownership, `.ssh` mode `0700` and `authorized_keys` mode `0600`. Unsafe paths and symlinks are rejected. Existing authentication restrictions are not silently widened to make an uploaded key work. The guest's configured key path and authentication settings must support the requested change; an offline configuration check is not a successful remote login test.

For SELinux guests, Forge explicitly labels the affected SSH and account paths using the guest policy, checks the stored labels against that policy, and verifies they remain unchanged before export. Existing home directories receive a label correction without recursively relabeling their unrelated contents. Missing tools, unusable labels or unsupported key-file contexts block publication. This avoids relying solely on a deferred first-boot relabel; it does not execute the guest's enforcing SELinux policy inside the appliance. [Libguestfs SELinux support](https://libguestfs.org/guestfs.3.html#selinux)

The supported launch path uses a standard `ssh.service` or `sshd.service`. Custom service overrides, alternative daemon configuration or key-file paths, conditional access restrictions and multi-method authentication may require manual review. Forge stops rather than bypassing those controls. The account picker lists local login accounts; directory-service accounts are outside this workflow.

For cloud-init images, password disabling also writes a managed `ssh_pwauth: false` configuration. SSH access changes follow other guest preparation, and the final image is checked before export. Cloud-init can apply account settings to existing users at first boot: creating an account with the provider's default username can therefore cause its configured sudo privileges to be applied later. Forge's account checks cover the exported image's present policy. Later cloud user-data, configuration management or startup scripts can also change the policy. Test SSH access and account privileges after launching the exported image on its intended destination. [Cloud-init users and groups](https://docs.cloud-init.io/en/latest/reference/modules.html#users-and-groups)

## Recipe API

`POST /api/images/{image_id}/build` accepts an optional `ssh_access` object:

```json
{
  "ssh_access": {
    "disable_password_auth": true,
    "users": [
      {
        "username": "operator",
        "create": true,
        "authorized_keys": ["ssh-ed25519 <replace-with-public-key-data> workstation"]
      }
    ]
  }
}
```

Replace the example key with a complete public key. Set `create` to `false` for an existing account. Omit `ssh_access`, or leave both its password flag false and its user list empty, for no changes. Invalid key input is rejected without echoing its contents into validation errors. Public keys are part of the saved recipe and exported authorized-key file; private keys are never required.

## Validation record

On 2026-10-28, the backend suite passed 593 tests and 118 subtests. The Access UI passed 128 browser assertions covering wizard navigation, draft retention, file selection, key validation, review summaries, asynchronous uploads and responsive layout.

Native ARM64 validation used checksum-verified Debian 12 and Oracle Linux 9.8 cloud images with the direct/TCG backend. Full image-engine builds and QCOW2 exports were exercised first. After the SELinux and tool-version corrections, the final code and Docker image passed 108 focused runtime checks using fresh copies of both prepared sources: 47 for Debian and 61 for Oracle. These final runs reused the immutable sources' inspections and exercised SSH preparation, final receipts, conversion, byte comparison and independent readback without repeating unrelated boot/storage scans.

The fixtures included an existing account, a restricted authorized-key entry and deliberately enabled password authentication in global, included and conditional settings. Preparation preserved the existing entry, skipped the same key with a different comment, appended a new key, created a separate user with an unusable password and no supplementary groups, and disabled the loaded password and keyboard-interactive settings. Oracle's affected paths matched its SELinux policy, while an unrelated existing-home file retained its deliberately distinct label. Original and seeded source fingerprints were unchanged.

On disposable verification overlays, both existing and new accounts authenticated with ephemeral keys through appliance loopback. Password and keyboard-interactive authentication were unavailable, and the new account had no sudo grant. The probes had no external network access; their private keys were removed and the exports' hashes were unchanged. These checks did not perform a firmware boot or a destination cloud launch, and the product's offline validation result still reports `login_tested: false`.
