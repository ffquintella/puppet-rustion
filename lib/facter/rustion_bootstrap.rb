# Detects whether the rustion bastion has completed its interactive
# first-start bootstrap on this node. The bootstrap creates the default
# admin user YAML and the credential encryption master key; both must be
# present before the systemd service can start non-interactively.
#
# Resolves to a hash:
#   rustion_bootstrap.complete       -> Boolean
#   rustion_bootstrap.admin_present  -> Boolean
#   rustion_bootstrap.credential_key -> Boolean
#
# Paths follow the module defaults under /srv/application-config/rustion.
# If you override `config_dir`, set `rustion::bootstrap_complete` explicitly
# in Hiera; the fact only reads the default path.
Facter.add(:rustion_bootstrap) do
  confine kernel: 'Linux'
  setcode do
    config_dir = '/srv/application-config/rustion'
    users_dir  = File.join(config_dir, 'users')
    cred_key   = File.join(config_dir, 'credential_key')

    admin_present = File.exist?(File.join(users_dir, 'admin.yaml')) ||
                    (Dir.exist?(users_dir) && !Dir.glob(File.join(users_dir, '*.yaml')).empty?)
    cred_present  = File.exist?(cred_key)

    {
      'complete'       => admin_present && cred_present,
      'admin_present'  => admin_present,
      'credential_key' => cred_present,
    }
  end
end
