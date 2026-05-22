# puppet-rustion

Puppet module for installing and configuring the [Rustion](https://github.com/ffquintella/Rustion) bastion server.

Rustion is a security-first bastion/jump server that proxies SSH, RDP, and SMB connections with session recording and tamper-proof audit logging. It supports post-quantum cryptography (hybrid ML-KEM-768 + X25519, ML-DSA-65 + Ed25519) as the default cipher suite.

## Table of Contents

- [Requirements](#requirements)
- [Usage](#usage)
- [Parameters](#parameters)
- [Managed Resources](#managed-resources)
- [Examples](#examples)
- [Testing](#testing)
- [License](#license)

## Requirements

- Puppet >= 7.24 < 9.0.0
- [puppetlabs/stdlib](https://forge.puppet.com/modules/puppetlabs/stdlib) >= 9.0.0 < 10.0.0

### Supported Operating Systems

- Oracle Linux 8, 9
- Red Hat Enterprise Linux 9
- Ubuntu 22.04

## Usage

### Basic

```puppet
include rustion
```

This installs the `rustion` package, creates the system user/group, sets up all required directories with hardened permissions, writes the default configuration, deploys the systemd unit file, and starts the service.

### Hiera

```yaml
rustion::ssh_listen: '0.0.0.0:2222'
rustion::rdp_listen: '0.0.0.0:3389'
rustion::smb_listen: '0.0.0.0:4445'
rustion::cipher_suite: 'hybrid-pqc'
rustion::mfa_required: true
```

## Parameters

### Package & Service

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `package_name` | `String` | `'rustion'` | Package name |
| `package_name` | `String` | `'rustion-server'` | Name of the Rustion package |
| `package_ensure` | `String` | `'present'` | Package ensure value (used when `version` is unset) |
| `manage_package` | `Boolean` | `true` | Set to `false` to install rustion out-of-band and skip the `Package` resource |
| `manage_repo` | `Boolean` | `false` | Manage a yumrepo / apt source for rustion before installing the package |
| `repo_baseurl` | `Optional[String]` | `undef` | Base URL of the rustion package repository (required when `manage_repo` is true) |
| `repo_gpgkey` | `Optional[String]` | `undef` | URL of the repository's GPG public key |
| `repo_gpgcheck` | `Boolean` | `true` | Enforce GPG verification of repository packages |
| `repo_name` | `String` | `'rustion'` | Repository title (yumrepo id / apt source filename) |
| `repo_descr` | `String` | `'Rustion Bastion Server'` | Human-readable repository description |
| `version` | `Optional[String]` | `undef` | Pin a specific Rustion package version (e.g. `'0.7.16'`). Overrides `package_ensure`. |
| `manage_user` | `Boolean` | `true` | Manage the rustion system user/group |
| `manage_service` | `Boolean` | `true` | Manage the systemd service |
| `service_name` | `String` | `'rustion'` | Systemd service name |
| `service_ensure` | `Stdlib::Ensure::Service` | `'running'` | Service ensure value |
| `service_enable` | `Boolean` | `true` | Enable on boot |
| `user` | `String` | `'rustion'` | System user |
| `group` | `String` | `'rustion'` | System group |
| `config_dir` | `Stdlib::Absolutepath` | `'/srv/application-config/rustion'` | Configuration directory (under baseapp's `/srv/application-config`) |
| `data_dir` | `Stdlib::Absolutepath` | `'/srv/application-data/rustion'` | Data directory (under baseapp's `/srv/application-data`) |
| `log_dir` | `Stdlib::Absolutepath` | `'/var/log/rustion'` | Log directory (matches the rustion binary default) |

### Server

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `ssh_listen` | `String` | `'127.0.0.1:2222'` | SSH proxy listen address |
| `rdp_listen` | `String` | `'127.0.0.1:3389'` | RDP gateway listen address |
| `smb_listen` | `String` | `'127.0.0.1:4445'` | SMB proxy listen address |
| `max_sessions` | `Integer` | `1000` | Maximum concurrent sessions |
| `idle_timeout_secs` | `Integer` | `1800` | Idle session timeout (seconds) |
| `max_session_duration_secs` | `Integer` | `28800` | Max session duration (seconds) |
| `rdp_nla_enabled` | `Boolean` | `false` | Enable NLA/CredSSP relay for RDP |
| `rdp_pqc_tls` | `Boolean` | `false` | Enable post-quantum TLS for RDP |

### Cryptography

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `cipher_suite` | `Enum['hybrid-pqc', 'pure-pqc', 'classical']` | `'hybrid-pqc'` | Cipher suite |
| `pqc_kem` | `Enum['ml-kem-512', 'ml-kem-768', 'ml-kem-1024']` | `'ml-kem-768'` | Post-quantum KEM |
| `pqc_sig` | `Enum['ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87']` | `'ml-dsa-65'` | Post-quantum signature |
| `classical_kem` | `String` | `'x25519'` | Classical KEM |
| `classical_sig` | `String` | `'ed25519'` | Classical signature |
| `symmetric` | `Enum['aes-256-gcm', 'chacha20-poly1305']` | `'aes-256-gcm'` | Symmetric cipher |

### Authentication

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `password_auth` | `Boolean` | `true` | Enable password authentication |
| `certificate_auth` | `Boolean` | `true` | Enable certificate authentication |
| `saml_auth` | `Boolean` | `false` | Enable SAML 2.0 authentication |
| `mfa_required` | `Boolean` | `true` | Require multi-factor authentication |
| `ca_cert_path` | `Optional[Stdlib::Absolutepath]` | `undef` | CA certificate path |
| `rate_limit_attempts` | `Integer` | `5` | Max auth attempts before rate limiting |
| `rate_limit_window_secs` | `Integer` | `60` | Rate limit window (seconds) |

### MFA Methods

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `mfa_totp` | `Boolean` | `true` | Enable TOTP |
| `mfa_fido2` | `Boolean` | `true` | Enable FIDO2/WebAuthn |
| `mfa_yubikey` | `Boolean` | `false` | Enable YubiKey OTP |

### SAML (only rendered when `saml_auth => true`)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `saml_idp_metadata_url` | `Optional[String]` | `undef` | IdP metadata URL |
| `saml_idp_metadata_path` | `Optional[Stdlib::Absolutepath]` | `undef` | IdP metadata local path |
| `saml_sp_entity_id` | `Optional[String]` | `undef` | SP entity ID |
| `saml_sp_acs_url` | `Optional[String]` | `undef` | SP ACS URL |
| `saml_role_attribute` | `String` | `'memberOf'` | Role mapping attribute |
| `saml_username_attribute` | `String` | `'uid'` | Username attribute |

### Audit & Recording

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `audit_checkpoint_interval` | `Integer` | `1000` | Merkle checkpoint interval |
| `audit_verify_on_startup` | `Boolean` | `true` | Verify chain on startup |
| `ssh_record_input` | `Boolean` | `false` | Record SSH keystrokes (off by default) |
| `recording_retention_days` | `Integer` | `90` | Recording retention (days) |

### Optional Data

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `users` | `Optional[Hash]` | `undef` | User definitions (creates YAML files) |
| `targets` | `Optional[Hash]` | `undef` | Target definitions (creates YAML files) |
| `roles` | `Optional[Hash]` | `undef` | Role definitions (creates YAML files) |

### SELinux (optional)

When `manage_selinux => true`, the module includes the `rustion::selinux`
class which labels the rustion directories and listening ports via
`semanage` / `restorecon`. A no-op on Debian-family hosts and on any host
where SELinux is disabled at runtime (every exec is guarded by
`selinuxenabled`). Implemented with `exec` resources, so no extra Puppet
module dependency is required.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `manage_selinux` | `Boolean` | `false` | Enable SELinux labeling for rustion paths and ports |
| `selinux_config_type` | `String` | `'etc_t'` | File context type for `config_dir` |
| `selinux_data_type` | `String` | `'var_lib_t'` | File context type for `data_dir` |
| `selinux_log_type` | `String` | `'var_log_t'` | File context type for `log_dir` |
| `selinux_run_type` | `String` | `'var_run_t'` | File context type for `/var/run/rustion` |
| `selinux_ssh_port_type` | `String` | `'ssh_port_t'` | Port type for the SSH listener |
| `selinux_rdp_port_type` | `String` | `'rdp_port_t'` | Port type for the RDP listener |
| `selinux_smb_port_type` | `String` | `'smbd_port_t'` | Port type for the SMB listener |
| `selinux_bastionvault_port_type` | `String` | `'http_port_t'` | Port type for the BastionVault control-plane listener (only labeled when `bastionvault_enabled` is true) |

### BastionVault Control-Plane Integration

Renders the `[control_plane]` and `[control_plane.health]` sections in
`rustion.toml` and manages the on-disk directories the
`rustion-control-plane` crate expects. See
[`docs/bastionvault-integration.md`](https://github.com/ffquintella/Rustion/blob/main/docs/bastionvault-integration.md)
in the Rustion repo for the full integration spec.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `bastionvault_enabled` | `Boolean` | `false` | Enable the BastionVault control plane |
| `bastionvault_listen` | `String` | `'0.0.0.0:9443'` | TLS listen address (SocketAddr) for the control plane — renders as `listen` |
| `bastionvault_tls_cert_path` | `Optional[Stdlib::Absolutepath]` | `undef` | TLS certificate path. When undef and `bastionvault_enabled` is true, the module auto-generates one (see `bastionvault_manage_tls`). Defaults to `${bastionvault_identity_dir}/tls.crt`. |
| `bastionvault_tls_key_path` | `Optional[Stdlib::Absolutepath]` | `undef` | TLS private key path. Same semantics as `bastionvault_tls_cert_path`. Defaults to `${bastionvault_identity_dir}/tls.key`. |
| `bastionvault_manage_tls` | `Boolean` | `true` | Auto-generate a self-signed Ed25519 cert + key under `${bastionvault_identity_dir}` when `bastionvault_enabled` is true and both cert/key paths are left undef. Set false to require operator-provisioned cert/key. |
| `bastionvault_tls_cert_days` | `Integer[1]` | `3650` | Validity period (days) of the auto-generated self-signed cert. |
| `bastionvault_tls_cert_subject` | `Optional[String]` | `undef` | Subject DN for the self-signed cert (`openssl req -subj`). Defaults to `/CN=<fqdn>` from the `networking.fqdn` fact. |
| `bastionvault_client_ca_path` | `Optional[Stdlib::Absolutepath]` | `undef` | PEM bundle of trusted client-cert CAs; enables BV-pinned mTLS when set |
| `bastionvault_identity_dir` | `Optional[Stdlib::Absolutepath]` | `${config_dir}/control-plane` | Directory holding the ML-KEM-768 identity keypair (`identity.pub` / `identity.key`); generated on first run |
| `bastionvault_authorities_dir` | `Optional[Stdlib::Absolutepath]` | `${config_dir}/authorities` | Approved authority YAML directory |
| `bastionvault_manage_authority_dirs` | `Boolean` | `true` | Manage the authority / pending / tombstoned / identity directories |
| `bastionvault_ssh_advertise` | `String` | `''` | host:port advertised back to BV for SSH dialing (empty = use `ssh_listen`) |
| `bastionvault_rdp_advertise` | `String` | `''` | host:port advertised back to BV for RDP dialing (empty = use `rdp_listen`) |
| `bastionvault_replay_window` | `Integer[1]` | `8192` | Replay-window LRU capacity (in-memory nonce cache) |
| `bastionvault_telemetry_rate_capacity` | `Integer[1]` | `60` | Telemetry token-bucket capacity per (IP, authority) |
| `bastionvault_telemetry_rate_refill` | `String` | `'1.0'` | Telemetry token-bucket refill rate, tokens/sec (decimal string, emitted as TOML f64) |
| `bastionvault_authorities` | `Optional[Hash]` | `undef` | Approved authority records to drop into `authorities_dir` as YAML (GitOps path) |

## Managed Resources

### Directories

| Path | Owner | Group | Mode |
|------|-------|-------|------|
| `/srv/application-config/rustion/` | rustion | rustion | 0750 |
| `/srv/application-config/rustion/audit-keys/` | root | rustion | 0750 |
| `/srv/application-config/rustion/users/` | rustion | rustion | 0750 |
| `/srv/application-config/rustion/targets/` | rustion | rustion | 0750 |
| `/srv/application-config/rustion/roles/` | rustion | rustion | 0750 |
| `/var/log/rustion/` | rustion | rustion | 0750 |
| `/var/log/rustion/audit/` | rustion | rustion | 0750 |
| `/srv/application-data/rustion/` | rustion | rustion | 0750 |
| `/srv/application-data/rustion/recordings/` | rustion | rustion | 0750 |
| `/var/run/rustion/` | rustion | rustion | 0755 |
| `/srv/application-config/rustion/control-plane/` *(if BV enabled)* | root | rustion | 0750 |
| `/srv/application-config/rustion/authorities/` *(if BV enabled)* | rustion | rustion | 0750 |
| `/srv/application-config/rustion/authorities-pending/` *(if BV enabled)* | rustion | rustion | 0750 |
| `/srv/application-config/rustion/tombstoned/` *(if BV enabled)* | rustion | rustion | 0750 |

The parent directories `/srv/application-config` and `/srv/application-data` are created by the [`ffquintella/baseapp`](https://github.com/ffquintella/puppet-baseapp) module, which this module pulls in as a dependency. Logs live under `/var/log/rustion` to match the rustion binary's built-in default.

### Configuration

- `/srv/application-config/rustion/rustion.toml` (owner: root, group: rustion, mode: 0640)

### Systemd

- `/usr/lib/systemd/system/rustion.service` with security hardening (NoNewPrivileges, ProtectSystem=strict, MemoryDenyWriteExecute, etc.)

## Examples

### Production with SAML SSO

```puppet
class { 'rustion':
  ssh_listen            => '0.0.0.0:2222',
  rdp_listen            => '0.0.0.0:3389',
  smb_listen            => '0.0.0.0:4445',
  saml_auth             => true,
  saml_idp_metadata_url => 'https://idp.example.com/saml/metadata',
  saml_sp_entity_id     => 'https://bastion.example.com/saml',
  saml_sp_acs_url       => 'https://bastion.example.com/saml/acs',
}
```

### First-run admin user

Rustion refuses to start without at least one user — on first boot it prints
`No users found. Creating default admin account.` and tries to prompt for a
password on stdin, which fails under systemd
(`failed to read password: No such device or address`). Seed an admin via
the `users` param so the service can come up cleanly:

```puppet
class { 'rustion':
  users => {
    'admin' => {
      'username'      => 'admin',
      'password_hash' => 'argon2id$v=19$m=65536,t=3,p=4$...',
      'roles'         => ['admin'],
    },
  },
}
```

Generate the password hash out of band with `rustion user hash` (or whatever
your release ships) and store it in Hiera + eyaml.

### Pull rustion from a custom yum repository

```puppet
class { 'rustion':
  manage_repo  => true,
  repo_baseurl => 'https://repo.example.com/rustion/el9/',
  repo_gpgkey  => 'https://repo.example.com/rustion/RPM-GPG-KEY-rustion',
}
```

### Install rustion out-of-band (skip the Package resource)

```puppet
class { 'rustion':
  manage_package => false,
}
```

### Pin a specific Rustion version

```puppet
class { 'rustion':
  version => '0.7.16',
}
```

### Enable SELinux labeling

```puppet
class { 'rustion':
  manage_selinux => true,
}
```

### BastionVault control-plane integration

```puppet
class { 'rustion':
  bastionvault_enabled       => true,
  bastionvault_listen        => '0.0.0.0:9443',
  bastionvault_tls_cert_path => '/etc/rustion/control-plane/cert.pem',
  bastionvault_tls_key_path  => '/etc/rustion/control-plane/key.pem',
  bastionvault_authorities => {
    'bastion-vault-prod' => {
      'name'              => 'bastion-vault-prod',
      'type'              => 'external-vault',
      'pubkey'            => {
        'ed25519' => 'MCowBQYDK2VwAyEA...',
        'mldsa65' => 'MIIH...',
      },
      'allowed_targets'   => ['prod-*', '10.0.0.0/8'],
      'allowed_actions'   => ['open', 'renew', 'terminate'],
      'max_session_secs'  => 43_200,
      'replay_window_secs' => 300,
      'revoked'           => false,
    },
  },
}
```

> The `bastionvault_authorities` Hiera/Puppet path is the **GitOps** style — it
> drops approved records straight into `authorities/`. For the explicit
> submit-then-approve handshake, leave `bastionvault_authorities` undef and
> drive the workflow with the `rustion authority` CLI.

### Classical cryptography mode

```puppet
class { 'rustion':
  cipher_suite => 'classical',
}
```

### Pre-provisioned users and targets

```puppet
class { 'rustion':
  users   => {
    'admin' => {
      'username' => 'admin',
      'roles'    => ['admin'],
    },
  },
  targets => {
    'webserver' => {
      'hostname' => '10.0.1.10',
      'port'     => 22,
      'protocol' => 'ssh',
    },
  },
  roles   => {
    'admin' => {
      'name'    => 'admin',
      'targets' => ['*'],
    },
  },
}
```

## Testing

```bash
# Install dependencies (requires puppetlabs Ruby)
/opt/puppetlabs/puppet/bin/bundle install --path vendor/bundle

# Prepare fixtures
/opt/puppetlabs/puppet/bin/bundle exec rake spec_prep

# Run tests
/opt/puppetlabs/puppet/bin/bundle exec rspec spec/classes/
```

## License

MIT
