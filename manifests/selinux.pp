# SELinux configuration for the Rustion bastion server.
#
# Labels the rustion directories and listening ports via `semanage` /
# `restorecon` so the service can run with SELinux enforcing without policy
# violations.
#
# Included by `rustion` when `manage_selinux => true`. A no-op on
# Debian-family hosts and on hosts where SELinux is disabled at runtime
# (every exec is guarded by `selinuxenabled`).
#
# All inputs are read from the `rustion::` class scope rather than passed
# as parameters, so a resource-style declaration is not required.
#
# Implemented with `exec` resources rather than a hard dependency on
# `puppet/selinux` so the module stays self-contained.
#
class rustion::selinux {

  if $facts['os']['family'] != 'RedHat' {
    notice("rustion::selinux: skipping SELinux configuration on ${facts['os']['family']} (RedHat-family only).")
  } else {

    $config_dir                     = $rustion::config_dir
    $data_dir                       = $rustion::data_dir
    $log_dir                        = $rustion::log_dir
    $ssh_listen                     = $rustion::ssh_listen
    $rdp_listen                     = $rustion::rdp_listen
    $smb_listen                     = $rustion::smb_listen
    $bastionvault_enabled           = $rustion::bastionvault_enabled
    $bastionvault_bind              = $rustion::bastionvault_bind
    $selinux_config_type            = $rustion::selinux_config_type
    $selinux_data_type              = $rustion::selinux_data_type
    $selinux_log_type               = $rustion::selinux_log_type
    $selinux_run_type               = $rustion::selinux_run_type
    $selinux_ssh_port_type          = $rustion::selinux_ssh_port_type
    $selinux_rdp_port_type          = $rustion::selinux_rdp_port_type
    $selinux_smb_port_type          = $rustion::selinux_smb_port_type
    $selinux_bastionvault_port_type = $rustion::selinux_bastionvault_port_type

    $exec_path = ['/usr/sbin', '/usr/bin', '/sbin', '/bin']
    $guard     = 'selinuxenabled'

    # --- File contexts ---

    rustion::selinux::fcontext { 'rustion-config':
      path      => $config_dir,
      seltype   => $selinux_config_type,
      exec_path => $exec_path,
      guard     => $guard,
    }

    rustion::selinux::fcontext { 'rustion-data':
      path      => $data_dir,
      seltype   => $selinux_data_type,
      exec_path => $exec_path,
      guard     => $guard,
    }

    rustion::selinux::fcontext { 'rustion-log':
      path      => $log_dir,
      seltype   => $selinux_log_type,
      exec_path => $exec_path,
      guard     => $guard,
    }

    rustion::selinux::fcontext { 'rustion-run':
      path      => '/var/run/rustion',
      seltype   => $selinux_run_type,
      exec_path => $exec_path,
      guard     => $guard,
    }

    # --- Ports ---
    # Listener strings are `host:port`; take the substring after the last `:`.

    $ssh_port = regsubst($ssh_listen, '^.*:', '')
    $rdp_port = regsubst($rdp_listen, '^.*:', '')
    $smb_port = regsubst($smb_listen, '^.*:', '')

    rustion::selinux::port { "rustion-ssh-${ssh_port}":
      port      => $ssh_port,
      protocol  => 'tcp',
      seltype   => $selinux_ssh_port_type,
      exec_path => $exec_path,
      guard     => $guard,
    }

    rustion::selinux::port { "rustion-rdp-${rdp_port}":
      port      => $rdp_port,
      protocol  => 'tcp',
      seltype   => $selinux_rdp_port_type,
      exec_path => $exec_path,
      guard     => $guard,
    }

    rustion::selinux::port { "rustion-smb-${smb_port}":
      port      => $smb_port,
      protocol  => 'tcp',
      seltype   => $selinux_smb_port_type,
      exec_path => $exec_path,
      guard     => $guard,
    }

    if $bastionvault_enabled {
      $bv_port = regsubst($bastionvault_bind, '^.*:', '')

      rustion::selinux::port { "rustion-bastionvault-${bv_port}":
        port      => $bv_port,
        protocol  => 'tcp',
        seltype   => $selinux_bastionvault_port_type,
        exec_path => $exec_path,
        guard     => $guard,
      }
    }
  }
}
