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
#   Package ensure value (present, latest, or a specific version)
# @param manage_user
#   Whether to manage the rustion system user and group
# @param manage_service
#   Whether to manage the systemd service
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
#   Base configuration directory
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
# @param users
#   Optional hash of user definitions to create as YAML files
# @param targets
#   Optional hash of target definitions to create as YAML files
# @param roles
#   Optional hash of role definitions to create as YAML files
#
class rustion (
  String                                               $package_name              = 'rustion',
  String                                               $package_ensure            = 'present',
  Boolean                                              $manage_user               = true,
  Boolean                                              $manage_service            = true,
  String                                               $service_name              = 'rustion',
  Stdlib::Ensure::Service                              $service_ensure            = 'running',
  Boolean                                              $service_enable            = true,
  String                                               $user                      = 'rustion',
  String                                               $group                     = 'rustion',
  Stdlib::Absolutepath                                 $config_dir                = '/opt/rustion',
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
  Optional[Hash]                                       $users                     = undef,
  Optional[Hash]                                       $targets                   = undef,
  Optional[Hash]                                       $roles                     = undef,
) {

  $config_file = "${config_dir}/rustion.toml"

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

  # --- Package ---

  package { $package_name:
    ensure  => $package_ensure,
    require => $manage_user ? {
      true  => User[$user],
      false => undef,
    },
  }

  # --- Directories ---

  file { $config_dir:
    ensure  => 'directory',
    owner   => $user,
    group   => $group,
    mode    => '0755',
    require => Package[$package_name],
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

  file { '/var/log/rustion':
    ensure  => 'directory',
    owner   => $user,
    group   => $group,
    mode    => '0750',
    require => Package[$package_name],
  }

  file { '/var/log/rustion/audit':
    ensure  => 'directory',
    owner   => $user,
    group   => $group,
    mode    => '0750',
    require => File['/var/log/rustion'],
  }

  file { '/var/lib/rustion':
    ensure  => 'directory',
    owner   => $user,
    group   => $group,
    mode    => '0750',
    require => Package[$package_name],
  }

  file { '/var/lib/rustion/recordings':
    ensure  => 'directory',
    owner   => $user,
    group   => $group,
    mode    => '0750',
    require => File['/var/lib/rustion'],
  }

  file { '/var/run/rustion':
    ensure  => 'directory',
    owner   => $user,
    group   => $group,
    mode    => '0755',
    require => Package[$package_name],
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
    }),
    require => File[$config_dir],
    notify  => $manage_service ? {
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
    notify => $manage_service ? {
      true  => Service[$service_name],
      false => undef,
    },
  }

  # --- Service ---

  if $manage_service {
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
        notify  => $manage_service ? {
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
        notify  => $manage_service ? {
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
        notify  => $manage_service ? {
          true  => Service[$service_name],
          false => undef,
        },
      }
    }
  }

}
