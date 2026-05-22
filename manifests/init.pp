# Installs and configures the Rustion bastion server
#
# @summary Manages the Rustion security-first bastion/jump server that proxies
#   SSH, RDP, and SMB with session recording and tamper-proof audit logging.
#
# @example Basic usage with defaults
#   include rustion
#
# @example Production deployment with custom listen addresses
#   class { 'rustion':
#     ssh_listen => '0.0.0.0:2222',
#     rdp_listen => '0.0.0.0:3389',
#     smb_listen => '0.0.0.0:4445',
#   }
#
# @example Classical crypto mode
#   class { 'rustion':
#     cipher_suite => 'classical',
#   }
#
# @param package_name
#   Name of the Rustion package
# @param package_ensure
#   Package ensure value (present, latest, or a specific version). Used as a
#   fallback when `version` is unset.
# @param version
#   Specific Rustion package version to install (e.g. `'0.7.16'`). When set,
#   overrides `package_ensure`. Leave undef and use `package_ensure` for
#   `'present'` / `'latest'` semantics.
# @param manage_user
#   Whether to manage the rustion system user and group
# @param manage_service
#   Whether to manage the systemd service
# @param bootstrap_complete
#   Force the bootstrap-complete state. The module also reads the
#   `rustion_bootstrap.complete` fact (true when both the default admin
#   user YAML and the credential master key exist under the default
#   `config_dir`) and starts the service when either signal is true.
#   Set this to true in Hiera only if you've overridden `config_dir` or
#   want to bypass auto-detection.
# @param manage_package
#   Whether to manage the rustion package. Set to false to install
#   rustion out-of-band (manual rpm/deb, container image, etc.) and let
#   Puppet manage only the user, directories, config, and service.
# @param manage_repo
#   Whether to create a package repository (yumrepo / apt source) for rustion
#   before installing the package. Requires `repo_baseurl`.
# @param repo_baseurl
#   Base URL of the rustion package repository (required when
#   `manage_repo` is true).
# @param repo_gpgkey
#   URL of the GPG public key used to sign the repository (optional).
# @param repo_gpgcheck
#   Whether to enforce GPG verification of repository packages.
# @param repo_name
#   Repository name (yumrepo title / apt source list filename).
# @param repo_descr
#   Human-readable repository description (`name=` line in yumrepo).
# @param service_name
#   Name of the systemd service
# @param service_ensure
#   Service ensure value
# @param service_enable
#   Whether to enable the service on boot
# @param user
#   System user that runs the service
# @param group
#   System group for the service
# @param config_dir
#   Base configuration directory (under /srv/application-config as defined by baseapp)
# @param data_dir
#   Base data directory (under /srv/application-data as defined by baseapp)
# @param log_dir
#   Base log directory (matches the rustion binary default of `/var/log/rustion`)
# @param ssh_host_key_path
#   Path to the persistent SSH host key (Ed25519, raw 32 bytes). Rustion
#   generates this on first run if missing. Defaults to
#   `${config_dir}/ssh_host_ed25519_key` so the file lives in a directory
#   the rustion user can write to. Must be stable across restarts to avoid
#   client host-key warnings.
# @param credential_key_path
#   Path to the AES-256 master key used to encrypt stored target credentials.
#   Rustion generates this on first run if missing. Defaults to
#   `${config_dir}/credential_key`.
# @param ssh_listen
#   SSH proxy listen address
# @param rdp_listen
#   RDP gateway listen address
# @param smb_listen
#   SMB proxy listen address
# @param max_sessions
#   Maximum concurrent sessions
# @param idle_timeout_secs
#   Idle session timeout in seconds
# @param max_session_duration_secs
#   Maximum session duration in seconds
# @param rdp_nla_enabled
#   Enable NLA/CredSSP relay for RDP
# @param rdp_pqc_tls
#   Enable post-quantum TLS for RDP
# @param cipher_suite
#   Cryptographic cipher suite
# @param pqc_kem
#   Post-quantum KEM algorithm
# @param pqc_sig
#   Post-quantum signature algorithm
# @param classical_kem
#   Classical KEM algorithm
# @param classical_sig
#   Classical signature algorithm
# @param symmetric
#   Symmetric encryption algorithm
# @param password_auth
#   Enable password authentication
# @param certificate_auth
#   Enable certificate authentication
# @param saml_auth
#   Enable SAML 2.0 authentication
# @param mfa_required
#   Require multi-factor authentication
# @param ca_cert_path
#   Path to CA certificate for client certificate validation
# @param rate_limit_attempts
#   Maximum authentication attempts before rate limiting
# @param rate_limit_window_secs
#   Rate limit sliding window in seconds
# @param mfa_totp
#   Enable TOTP MFA method
# @param mfa_fido2
#   Enable FIDO2/WebAuthn MFA method
# @param mfa_yubikey
#   Enable YubiKey OTP MFA method
# @param saml_idp_metadata_url
#   SAML IdP metadata URL
# @param saml_idp_metadata_path
#   SAML IdP metadata local file path
# @param saml_sp_entity_id
#   SAML Service Provider entity ID
# @param saml_sp_acs_url
#   SAML Assertion Consumer Service URL
# @param saml_role_attribute
#   SAML attribute for role mapping
# @param saml_username_attribute
#   SAML attribute for username extraction
# @param audit_checkpoint_interval
#   Merkle tree checkpoint interval (entries)
# @param audit_verify_on_startup
#   Verify audit chain integrity on startup
# @param ssh_record_input
#   Record SSH input keystrokes (off by default for security)
# @param recording_retention_days
#   Session recording retention in days
# @param log_file
#   Path to the daily-rotated JSON log file rustion writes to. Defaults to
#   `${log_dir}/rustion.log` so the rustion binary stays inside the
#   `ReadWritePaths` whitelist of the systemd unit.
# @param console_format
#   Console log format (`json` for structured logs, `text` for human-readable).
# @param log_level
#   Rustion log level (`trace`, `debug`, `info`, `warn`, `error`).
# @param users
#   Optional hash of user definitions to create as YAML files
# @param targets
#   Optional hash of target definitions to create as YAML files
# @param roles
#   Optional hash of role definitions to create as YAML files
# @param bastionvault_enabled
#   Enable the BastionVault control-plane integration (renders `[control_plane]`
#   in `rustion.toml`, manages `authorities/`, `authorities-pending/`,
#   `tombstoned/` and the control-plane identity directory).
# @param bastionvault_listen
#   Listen address (SocketAddr) for the BastionVault control-plane HTTPS endpoint.
#   Renders as `listen = ...` in `[control_plane]`.
# @param bastionvault_tls_cert_path
#   Path to the TLS certificate the control-plane listener serves. Required
#   when `bastionvault_enabled` is true; not managed by this module.
# @param bastionvault_tls_key_path
#   Path to the TLS private key for the control-plane listener. Required
#   when `bastionvault_enabled` is true; not managed by this module.
# @param bastionvault_client_ca_path
#   Optional path to a PEM bundle of trusted client-cert CAs. When set,
#   the control-plane listener requires mutual TLS - only clients
#   presenting a certificate signed by one of these CAs are admitted
#   (BV-pinned mTLS, recommended for production). Not managed by this
#   module; provision the bundle out-of-band (e.g. via a separate cert
#   distribution class). Ignored when `bastionvault_enabled` is false.
# @param bastionvault_identity_dir
#   Directory holding Rustion's ML-KEM-768 control-plane identity keypair
#   (`identity.pub` and `identity.key`). Generated on first run if missing.
#   Defaults to `${config_dir}/control-plane`.
# @param bastionvault_authorities_dir
#   Directory holding approved authority YAML files.
# @param bastionvault_manage_authority_dirs
#   Whether this module should create the authorities / authorities-pending /
#   tombstoned directories (always, so operators can stage pending YAMLs
#   before enabling the control plane) and the control-plane identity dir
#   (only when `bastionvault_enabled` is true). A commented sample file
#   `EXAMPLE.yaml.sample` is dropped in `authorities-pending/` for reference.
# @param bastionvault_ssh_advertise
#   host:port advertised back to BV for SSH dialing in the session-open
#   response. Empty string means "use `server.ssh_listen`".
# @param bastionvault_rdp_advertise
#   host:port advertised back to BV for RDP dialing. Empty string means
#   "use `server.rdp_listen`".
# @param bastionvault_replay_window
#   Replay-window LRU capacity (in-memory nonce cache). Must be > 0.
# @param bastionvault_telemetry_rate_capacity
#   Telemetry token-bucket capacity per (IP, authority) tuple.
# @param bastionvault_telemetry_rate_refill
#   Telemetry token-bucket refill rate, in tokens/sec. Decimal string (e.g.
#   `'1.0'`, `'0.5'`) - emitted verbatim into TOML as an `f64`.
# @param bastionvault_authorities
#   Optional hash of approved authority records to drop into
#   `authorities_dir` as YAML files. Use for GitOps-managed enrolment; for the
#   approval workflow, leave undef and use the `rustion authority` CLI.
# @param bastionvault_authorities_pending
#   Optional hash of pending authority enrolment requests to drop into
#   `authorities-pending/` as YAML files. The hash key becomes the filename
#   and the `name:` field if not set explicitly. Use this to stage the
#   `bvault rustion master export` output via Puppet/Hiera; an operator
#   still has to approve each entry with `rustion authority approve` and
#   reload the service. Managed independently of `bastionvault_enabled`.
# @param manage_selinux
#   When true, label the rustion directories and ports for SELinux via
#   `semanage` / `restorecon`. No-op on Debian-family hosts.
# @param selinux_config_type
#   SELinux file context type applied to `config_dir` (default `etc_t`).
# @param selinux_data_type
#   SELinux file context type applied to `data_dir` (default `var_lib_t`).
# @param selinux_log_type
#   SELinux file context type applied to `log_dir` (default `var_log_t`).
# @param selinux_run_type
#   SELinux file context type applied to `/var/run/rustion` (default `var_run_t`).
# @param selinux_ssh_port_type
#   SELinux port type for the SSH listener (default `ssh_port_t`).
# @param selinux_rdp_port_type
#   SELinux port type for the RDP listener (default `rdp_port_t`).
# @param selinux_smb_port_type
#   SELinux port type for the SMB listener (default `smbd_port_t`).
# @param selinux_bastionvault_port_type
#   SELinux port type for the BastionVault control-plane listener
#   (default `http_port_t`).
#
class rustion (
  String                                               $package_name              = 'rustion-server',
  String                                               $package_ensure            = 'present',
  Optional[String]                                     $version                   = undef,
  Boolean                                              $manage_user               = true,
  Boolean                                              $manage_service            = true,
  Boolean                                              $bootstrap_complete        = false,
  Boolean                                              $manage_package            = true,
  Boolean                                              $manage_repo               = false,
  Optional[String]                                     $repo_baseurl              = undef,
  Optional[String]                                     $repo_gpgkey               = undef,
  Boolean                                              $repo_gpgcheck             = true,
  String                                               $repo_name                 = 'rustion',
  String                                               $repo_descr                = 'Rustion Bastion Server',
  String                                               $service_name              = 'rustion',
  Stdlib::Ensure::Service                              $service_ensure            = 'running',
  Boolean                                              $service_enable            = true,
  String                                               $user                      = 'rustion',
  String                                               $group                     = 'rustion',
  Stdlib::Absolutepath                                 $config_dir                = '/srv/application-config/rustion',
  Stdlib::Absolutepath                                 $data_dir                  = '/srv/application-data/rustion',
  Stdlib::Absolutepath                                 $log_dir                   = '/var/log/rustion',
  Optional[Stdlib::Absolutepath]                       $ssh_host_key_path         = undef,
  Optional[Stdlib::Absolutepath]                       $credential_key_path       = undef,
  String                                               $ssh_listen                = '127.0.0.1:2222',
  String                                               $rdp_listen                = '127.0.0.1:3389',
  String                                               $smb_listen                = '127.0.0.1:4445',
  Integer                                              $max_sessions              = 1000,
  Integer                                              $idle_timeout_secs         = 1800,
  Integer                                              $max_session_duration_secs = 28800,
  Boolean                                              $rdp_nla_enabled           = false,
  Boolean                                              $rdp_pqc_tls              = false,
  Enum['hybrid-pqc', 'pure-pqc', 'classical']         $cipher_suite              = 'hybrid-pqc',
  Enum['ml-kem-512', 'ml-kem-768', 'ml-kem-1024']     $pqc_kem                   = 'ml-kem-768',
  Enum['ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87']         $pqc_sig                   = 'ml-dsa-65',
  String                                               $classical_kem             = 'x25519',
  String                                               $classical_sig             = 'ed25519',
  Enum['aes-256-gcm', 'chacha20-poly1305']             $symmetric                 = 'aes-256-gcm',
  Boolean                                              $password_auth             = true,
  Boolean                                              $certificate_auth          = true,
  Boolean                                              $saml_auth                 = false,
  Boolean                                              $mfa_required              = true,
  Optional[Stdlib::Absolutepath]                       $ca_cert_path              = undef,
  Integer                                              $rate_limit_attempts       = 5,
  Integer                                              $rate_limit_window_secs    = 60,
  Boolean                                              $mfa_totp                  = true,
  Boolean                                              $mfa_fido2                 = true,
  Boolean                                              $mfa_yubikey               = false,
  Optional[String]                                     $saml_idp_metadata_url     = undef,
  Optional[Stdlib::Absolutepath]                       $saml_idp_metadata_path    = undef,
  Optional[String]                                     $saml_sp_entity_id         = undef,
  Optional[String]                                     $saml_sp_acs_url           = undef,
  String                                               $saml_role_attribute       = 'memberOf',
  String                                               $saml_username_attribute   = 'uid',
  Integer                                              $audit_checkpoint_interval = 1000,
  Boolean                                              $audit_verify_on_startup   = true,
  Boolean                                              $ssh_record_input          = false,
  Integer                                              $recording_retention_days  = 90,
  Optional[Stdlib::Absolutepath]                       $log_file                  = undef,
  Enum['json', 'text']                                 $console_format            = 'json',
  Enum['trace', 'debug', 'info', 'warn', 'error']      $log_level                 = 'info',
  Optional[Hash]                                       $users                     = undef,
  Optional[Hash]                                       $targets                   = undef,
  Optional[Hash]                                       $roles                     = undef,
  Boolean                                              $bastionvault_enabled                          = false,
  String                                               $bastionvault_listen                           = '0.0.0.0:9443',
  Optional[Stdlib::Absolutepath]                       $bastionvault_tls_cert_path                    = undef,
  Optional[Stdlib::Absolutepath]                       $bastionvault_tls_key_path                     = undef,
  Boolean                                              $bastionvault_manage_tls                       = true,
  Integer[1]                                           $bastionvault_tls_cert_days                    = 3650,
  Optional[String]                                     $bastionvault_tls_cert_subject                 = undef,
  Optional[Stdlib::Absolutepath]                       $bastionvault_client_ca_path                   = undef,
  Optional[Stdlib::Absolutepath]                       $bastionvault_identity_dir                     = undef,
  Optional[Stdlib::Absolutepath]                       $bastionvault_authorities_dir                  = undef,
  Boolean                                              $bastionvault_manage_authority_dirs            = true,
  String                                               $bastionvault_ssh_advertise                    = '',
  String                                               $bastionvault_rdp_advertise                    = '',
  Integer                                              $bastionvault_replay_window                    = 8192,
  Integer                                              $bastionvault_telemetry_rate_capacity          = 60,
  String                                               $bastionvault_telemetry_rate_refill            = '1.0',
  Optional[Hash]                                       $bastionvault_authorities                      = undef,
  Optional[Hash]                                       $bastionvault_authorities_pending              = undef,
  Boolean                                              $manage_selinux                                = false,
  String                                               $selinux_config_type                           = 'etc_t',
  String                                               $selinux_data_type                             = 'var_lib_t',
  String                                               $selinux_log_type                              = 'var_log_t',
  String                                               $selinux_run_type                              = 'var_run_t',
  String                                               $selinux_ssh_port_type                         = 'ssh_port_t',
  String                                               $selinux_rdp_port_type                         = 'rdp_port_t',
  String                                               $selinux_smb_port_type                         = 'smbd_port_t',
  String                                               $selinux_bastionvault_port_type                = 'http_port_t',
) {

  $config_file = "${config_dir}/rustion.toml"

  # The first rustion start prompts on TTY for an admin password; under systemd
  # that always fails. Detect a completed bootstrap by looking for the admin
  # user YAML and credential master key that the interactive first-start
  # writes, and fall back to the explicit `bootstrap_complete` parameter for
  # operators who want to force the state via Hiera.
  $_rb_fact = $facts['rustion_bootstrap']
  $_fact_bootstrap = $_rb_fact ? {
    Hash    => $_rb_fact['complete'] ? {
      true    => true,
      default => false,
    },
    default => false,
  }
  $_bootstrap_complete = $bootstrap_complete or $_fact_bootstrap
  $_manage_service = $manage_service and $_bootstrap_complete

  if $manage_service and !$_bootstrap_complete {
    $_bootstrap_msg = "rustion: service not started - admin account has not been bootstrapped on this host. Run the interactive first-start as the rustion user to create the default admin: sudo -u ${user} ${service_name} serve --config ${config_dir}/${service_name}.toml ; follow the password prompt, then stop the process (Ctrl-C), then re-run the agent (auto-detected via the rustion_bootstrap fact, or set rustion::bootstrap_complete: true in Hiera to force)."

    notify { 'rustion-bootstrap-required':
      message  => $_bootstrap_msg,
      loglevel => 'warning',
    }
  }

  # `version` overrides `package_ensure` when set.
  $_package_ensure = $version ? {
    undef   => $package_ensure,
    default => $version,
  }

  $_log_file = $log_file ? {
    undef   => "${log_dir}/rustion.log",
    default => $log_file,
  }

  $_ssh_host_key_path = $ssh_host_key_path ? {
    undef   => "${config_dir}/ssh_host_ed25519_key",
    default => $ssh_host_key_path,
  }

  $_credential_key_path = $credential_key_path ? {
    undef   => "${config_dir}/credential_key",
    default => $credential_key_path,
  }

  # --- BastionVault control-plane defaults derived from $config_dir ---
  $_bv_identity_dir = $bastionvault_identity_dir ? {
    undef   => "${config_dir}/control-plane",
    default => $bastionvault_identity_dir,
  }
  $_bv_authorities_dir = $bastionvault_authorities_dir ? {
    undef   => "${config_dir}/authorities",
    default => $bastionvault_authorities_dir,
  }
  $_bv_pending_dir     = "${config_dir}/authorities-pending"
  $_bv_tombstoned_dir  = "${config_dir}/tombstoned"

  $_bv_tls_cert_path = $bastionvault_tls_cert_path ? {
    undef   => "${_bv_identity_dir}/tls.crt",
    default => $bastionvault_tls_cert_path,
  }
  $_bv_tls_key_path = $bastionvault_tls_key_path ? {
    undef   => "${_bv_identity_dir}/tls.key",
    default => $bastionvault_tls_key_path,
  }

  if $bastionvault_enabled and $bastionvault_manage_tls and $bastionvault_tls_cert_path == undef and $bastionvault_tls_key_path == undef {
    $_manage_bv_tls = true
  } else {
    $_manage_bv_tls = false
  }

  if $bastionvault_enabled and !$_manage_bv_tls {
    if $bastionvault_tls_cert_path == undef or $bastionvault_tls_key_path == undef {
      fail('rustion: bastionvault_tls_cert_path and bastionvault_tls_key_path are required when bastionvault_enabled is true (or leave both undef and set bastionvault_manage_tls => true to auto-generate a self-signed cert)')
    }
  }

  $_net = $facts['networking']
  $_fqdn = $_net ? {
    Hash    => $_net['fqdn'] ? {
      undef   => $_net['hostname'] ? {
        undef   => 'rustion',
        default => $_net['hostname'],
      },
      default => $_net['fqdn'],
    },
    default => 'rustion',
  }
  $_bv_tls_subject = $bastionvault_tls_cert_subject ? {
    undef   => "/CN=${_fqdn}",
    default => $bastionvault_tls_cert_subject,
  }

  # --- Base application directories under /srv ---
  # baseapp owner/group/mode can be tuned via Hiera (baseapp::owner, etc.).
  contain baseapp

  # --- User and group ---

  if $manage_user {
    group { $group:
      ensure => present,
      system => true,
    }

    user { $user:
      ensure     => present,
      system     => true,
      gid        => $group,
      home       => '/nonexistent',
      managehome => false,
      shell      => '/sbin/nologin',
      require    => Group[$group],
    }
  }

  # --- Package repository (optional) ---

  if $manage_repo {
    if $repo_baseurl == undef {
      fail('rustion: repo_baseurl is required when manage_repo is true')
    }

    $_os_family = $facts['os']['family']
    $_gpgcheck_str = $repo_gpgcheck ? {
      true  => '1',
      false => '0',
    }

    if $_os_family == 'RedHat' {
      yumrepo { $repo_name:
        ensure   => 'present',
        descr    => $repo_descr,
        baseurl  => $repo_baseurl,
        enabled  => '1',
        gpgcheck => $_gpgcheck_str,
        gpgkey   => $repo_gpgkey,
        before   => Package[$package_name],
      }
    } else {
      if $_os_family == 'Debian' {
        $_apt_list = "/etc/apt/sources.list.d/${repo_name}.list"

        file { $_apt_list:
          ensure  => 'file',
          owner   => 'root',
          group   => 'root',
          mode    => '0644',
          content => "deb ${repo_baseurl} stable main\n",
          before  => Package[$package_name],
        }

        if $repo_gpgkey {
          exec { "rustion-apt-key-${repo_name}":
            command => "/usr/bin/curl -fsSL ${repo_gpgkey} -o /etc/apt/keyrings/${repo_name}.gpg",
            creates => "/etc/apt/keyrings/${repo_name}.gpg",
            path    => ['/usr/bin', '/bin', '/usr/sbin', '/sbin'],
            before  => File[$_apt_list],
          }
        }

        exec { "rustion-apt-update-${repo_name}":
          command     => '/usr/bin/apt-get update',
          refreshonly => true,
          subscribe   => File[$_apt_list],
          before      => Package[$package_name],
        }
      } else {
        fail("rustion: manage_repo not supported on os.family '${_os_family}'")
      }
    }
  }

  # --- Package ---

  if $manage_package {
    package { $package_name:
      ensure  => $_package_ensure,
      require => $manage_user ? {
        true  => User[$user],
        false => undef,
      },
    }
  }

  # Dependency arrays used by directory / service resources so we can drop
  # the Package reference cleanly when `manage_package => false`.
  $_dir_require = $manage_package ? {
    true  => [Package[$package_name], Class['baseapp']],
    false => [Class['baseapp']],
  }
  $_pkg_require = $manage_package ? {
    true  => [Package[$package_name]],
    false => [],
  }

  # --- Directories ---

  file { $config_dir:
    ensure  => 'directory',
    owner   => $user,
    group   => $group,
    mode    => '0750',
    require => [Package[$package_name], Class['baseapp']],
  }

  file { "${config_dir}/audit-keys":
    ensure  => 'directory',
    owner   => 'root',
    group   => $group,
    mode    => '0750',
    require => File[$config_dir],
  }

  file { "${config_dir}/users":
    ensure  => 'directory',
    owner   => $user,
    group   => $group,
    mode    => '0750',
    require => File[$config_dir],
  }

  file { "${config_dir}/targets":
    ensure  => 'directory',
    owner   => $user,
    group   => $group,
    mode    => '0750',
    require => File[$config_dir],
  }

  file { "${config_dir}/roles":
    ensure  => 'directory',
    owner   => $user,
    group   => $group,
    mode    => '0750',
    require => File[$config_dir],
  }

  file { $log_dir:
    ensure  => 'directory',
    owner   => $user,
    group   => $group,
    mode    => '0750',
    require => [Package[$package_name], Class['baseapp']],
  }

  file { "${log_dir}/audit":
    ensure  => 'directory',
    owner   => $user,
    group   => $group,
    mode    => '0750',
    require => File[$log_dir],
  }

  file { $data_dir:
    ensure  => 'directory',
    owner   => $user,
    group   => $group,
    mode    => '0750',
    require => [Package[$package_name], Class['baseapp']],
  }

  file { "${data_dir}/recordings":
    ensure  => 'directory',
    owner   => $user,
    group   => $group,
    mode    => '0750',
    require => File[$data_dir],
  }

  file { '/var/run/rustion':
    ensure  => 'directory',
    owner   => $user,
    group   => $group,
    mode    => '0755',
    require => $_pkg_require,
  }

  # --- BastionVault control-plane directories ---
  #
  # Managed regardless of `bastionvault_enabled` so operators can stage
  # pending authority YAMLs ahead of enabling the control plane. The
  # control-plane identity directory still only appears when bastionvault
  # is actually turned on, since it holds the hybrid keypair.

  if $bastionvault_manage_authority_dirs {
    file { $_bv_authorities_dir:
      ensure  => 'directory',
      owner   => $user,
      group   => $group,
      mode    => '0750',
      require => File[$config_dir],
    }

    file { $_bv_pending_dir:
      ensure  => 'directory',
      owner   => $user,
      group   => $group,
      mode    => '0750',
      require => File[$config_dir],
    }

    file { $_bv_tombstoned_dir:
      ensure  => 'directory',
      owner   => $user,
      group   => $group,
      mode    => '0750',
      require => File[$config_dir],
    }

    file { "${_bv_pending_dir}/EXAMPLE.yaml.sample":
      ensure  => 'file',
      owner   => $user,
      group   => $group,
      mode    => '0640',
      source  => 'puppet:///modules/rustion/authority-pending.yaml.sample',
      require => File[$_bv_pending_dir],
    }
  }

  if $bastionvault_enabled and ($bastionvault_manage_authority_dirs or $_manage_bv_tls) {
    file { $_bv_identity_dir:
      ensure  => 'directory',
      owner   => 'root',
      group   => $group,
      mode    => '0750',
      require => File[$config_dir],
    }
  }

  # --- BastionVault self-signed control-plane TLS (optional) ---
  #
  # Generates an Ed25519 self-signed cert + key pair the first time the
  # agent runs with `bastionvault_enabled => true` and no operator-provided
  # cert/key. Pin the resulting cert into BV's trust store for production,
  # or swap in your own PKI by setting `bastionvault_tls_cert_path` /
  # `bastionvault_tls_key_path` explicitly.

  if $_manage_bv_tls {
    exec { 'rustion-bv-tls-selfsigned':
      command => "openssl req -x509 -newkey ed25519 -nodes -keyout ${_bv_tls_key_path} -out ${_bv_tls_cert_path} -days ${bastionvault_tls_cert_days} -subj '${_bv_tls_subject}'",
      creates => $_bv_tls_cert_path,
      path    => ['/usr/bin', '/bin', '/usr/sbin', '/sbin'],
      require => File[$_bv_identity_dir],
    }

    file { $_bv_tls_cert_path:
      ensure  => 'file',
      owner   => 'root',
      group   => $group,
      mode    => '0644',
      require => Exec['rustion-bv-tls-selfsigned'],
    }

    file { $_bv_tls_key_path:
      ensure  => 'file',
      owner   => 'root',
      group   => $group,
      mode    => '0640',
      require => Exec['rustion-bv-tls-selfsigned'],
    }
  }

  # --- Configuration file ---

  file { $config_file:
    ensure  => 'file',
    owner   => 'root',
    group   => $group,
    mode    => '0640',
    content => epp('rustion/rustion.toml.epp', {
        ssh_listen                => $ssh_listen,
        rdp_listen                => $rdp_listen,
        smb_listen                => $smb_listen,
        max_sessions              => $max_sessions,
        idle_timeout_secs         => $idle_timeout_secs,
        max_session_duration_secs => $max_session_duration_secs,
        rdp_nla_enabled           => $rdp_nla_enabled,
        rdp_pqc_tls              => $rdp_pqc_tls,
        ssh_host_key_path         => $_ssh_host_key_path,
        credential_key_path       => $_credential_key_path,
        cipher_suite              => $cipher_suite,
        pqc_kem                   => $pqc_kem,
        pqc_sig                   => $pqc_sig,
        classical_kem             => $classical_kem,
        classical_sig             => $classical_sig,
        symmetric                 => $symmetric,
        password_auth             => $password_auth,
        certificate_auth          => $certificate_auth,
        saml_auth                 => $saml_auth,
        mfa_required              => $mfa_required,
        ca_cert_path              => $ca_cert_path,
        rate_limit_attempts       => $rate_limit_attempts,
        rate_limit_window_secs    => $rate_limit_window_secs,
        mfa_totp                  => $mfa_totp,
        mfa_fido2                 => $mfa_fido2,
        mfa_yubikey               => $mfa_yubikey,
        saml_idp_metadata_url     => $saml_idp_metadata_url,
        saml_idp_metadata_path    => $saml_idp_metadata_path,
        saml_sp_entity_id         => $saml_sp_entity_id,
        saml_sp_acs_url           => $saml_sp_acs_url,
        saml_role_attribute       => $saml_role_attribute,
        saml_username_attribute   => $saml_username_attribute,
        audit_checkpoint_interval => $audit_checkpoint_interval,
        audit_verify_on_startup   => $audit_verify_on_startup,
        ssh_record_input          => $ssh_record_input,
        recording_retention_days  => $recording_retention_days,
        config_dir                => $config_dir,
        data_dir                  => $data_dir,
        log_dir                   => $log_dir,
        log_file                  => $_log_file,
        console_format            => $console_format,
        log_level                 => $log_level,
        bastionvault_enabled                  => $bastionvault_enabled,
        bastionvault_listen                   => $bastionvault_listen,
        bastionvault_tls_cert_path            => $_bv_tls_cert_path,
        bastionvault_tls_key_path             => $_bv_tls_key_path,
        bastionvault_client_ca_path           => $bastionvault_client_ca_path,
        bastionvault_identity_dir             => $_bv_identity_dir,
        bastionvault_authorities_dir          => $_bv_authorities_dir,
        bastionvault_ssh_advertise            => $bastionvault_ssh_advertise,
        bastionvault_rdp_advertise            => $bastionvault_rdp_advertise,
        bastionvault_replay_window            => $bastionvault_replay_window,
        bastionvault_telemetry_rate_capacity  => $bastionvault_telemetry_rate_capacity,
        bastionvault_telemetry_rate_refill    => $bastionvault_telemetry_rate_refill,
    }),
    require => File[$config_dir],
    notify  => $_manage_service ? {
      true  => Service[$service_name],
      false => undef,
    },
  }

  # --- Systemd unit file ---

  file { "/usr/lib/systemd/system/${service_name}.service":
    ensure => 'file',
    owner  => 'root',
    group  => 'root',
    mode   => '0644',
    source => 'puppet:///modules/rustion/rustion.service',
    notify => $_manage_service ? {
      true  => Service[$service_name],
      false => undef,
    },
  }

  # --- Service ---

  if $_manage_service {
    service { $service_name:
      ensure    => $service_ensure,
      enable    => $service_enable,
      require   => [
        File[$config_file],
        File["/usr/lib/systemd/system/${service_name}.service"],
      ],
      subscribe => File[$config_file],
    }
  }

  # --- Optional user/target/role YAML files ---

  if $users {
    $users.each |String $name, Hash $data| {
      file { "${config_dir}/users/${name}.yaml":
        ensure  => 'file',
        owner   => $user,
        group   => $group,
        mode    => '0640',
        content => stdlib::to_yaml($data),
        require => File["${config_dir}/users"],
        notify  => $_manage_service ? {
          true  => Service[$service_name],
          false => undef,
        },
      }
    }
  }

  if $targets {
    $targets.each |String $name, Hash $data| {
      file { "${config_dir}/targets/${name}.yaml":
        ensure  => 'file',
        owner   => $user,
        group   => $group,
        mode    => '0640',
        content => stdlib::to_yaml($data),
        require => File["${config_dir}/targets"],
        notify  => $_manage_service ? {
          true  => Service[$service_name],
          false => undef,
        },
      }
    }
  }

  if $roles {
    $roles.each |String $name, Hash $data| {
      file { "${config_dir}/roles/${name}.yaml":
        ensure  => 'file',
        owner   => $user,
        group   => $group,
        mode    => '0640',
        content => stdlib::to_yaml($data),
        require => File["${config_dir}/roles"],
        notify  => $_manage_service ? {
          true  => Service[$service_name],
          false => undef,
        },
      }
    }
  }

  # --- BastionVault approved-authority YAML files (GitOps path) ---

  if $bastionvault_enabled and $bastionvault_authorities {
    $bastionvault_authorities.each |String $name, Hash $data| {
      file { "${_bv_authorities_dir}/${name}.yaml":
        ensure  => 'file',
        owner   => $user,
        group   => $group,
        mode    => '0640',
        content => stdlib::to_yaml($data),
        require => $bastionvault_manage_authority_dirs ? {
          true  => File[$_bv_authorities_dir],
          false => File[$config_dir],
        },
        notify  => $_manage_service ? {
          true  => Service[$service_name],
          false => undef,
        },
      }
    }
  }

  # --- BastionVault pending-authority YAML files ---
  #
  # Dropped into `authorities-pending/` for the operator-driven approval
  # flow (`rustion authority list-pending` / `approve`). The `name:` field
  # defaults to the hash key when not set explicitly, and `schema_version`
  # defaults to 1. Service is not notified because pending files don't
  # affect runtime until approved.

  if $bastionvault_authorities_pending {
    $bastionvault_authorities_pending.each |String $name, Hash $data| {
      $_pending_payload = { 'schema_version' => 1, 'name' => $name }.merge($data)
      file { "${_bv_pending_dir}/${name}.yaml":
        ensure  => 'file',
        owner   => $user,
        group   => $group,
        mode    => '0640',
        content => stdlib::to_yaml($_pending_payload),
        require => $bastionvault_manage_authority_dirs ? {
          true  => File[$_bv_pending_dir],
          false => File[$config_dir],
        },
      }
    }
  }

  # --- Optional SELinux configuration ---

  if $manage_selinux {
    include rustion::selinux
  }

}
