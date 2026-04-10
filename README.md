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
| `package_ensure` | `String` | `'present'` | Package ensure value |
| `manage_user` | `Boolean` | `true` | Manage the rustion system user/group |
| `manage_service` | `Boolean` | `true` | Manage the systemd service |
| `service_name` | `String` | `'rustion'` | Systemd service name |
| `service_ensure` | `Stdlib::Ensure::Service` | `'running'` | Service ensure value |
| `service_enable` | `Boolean` | `true` | Enable on boot |
| `user` | `String` | `'rustion'` | System user |
| `group` | `String` | `'rustion'` | System group |
| `config_dir` | `Stdlib::Absolutepath` | `'/opt/rustion'` | Configuration directory |

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

## Managed Resources

### Directories

| Path | Owner | Group | Mode |
|------|-------|-------|------|
| `/opt/rustion/` | rustion | rustion | 0755 |
| `/opt/rustion/audit-keys/` | root | rustion | 0750 |
| `/opt/rustion/users/` | rustion | rustion | 0750 |
| `/opt/rustion/targets/` | rustion | rustion | 0750 |
| `/opt/rustion/roles/` | rustion | rustion | 0750 |
| `/var/log/rustion/audit/` | rustion | rustion | 0750 |
| `/var/lib/rustion/recordings/` | rustion | rustion | 0750 |
| `/var/run/rustion/` | rustion | rustion | 0755 |

### Configuration

- `/opt/rustion/rustion.toml` (owner: root, group: rustion, mode: 0640)

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
