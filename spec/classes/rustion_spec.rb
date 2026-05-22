require 'spec_helper'

describe 'rustion' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      context 'with default parameters' do
        it { is_expected.to compile }

        # Package
        it { is_expected.to contain_package('rustion-server').with_ensure('present') }

        # User and group
        it { is_expected.to contain_group('rustion').with_ensure('present').with_system(true) }
        it {
          is_expected.to contain_user('rustion')
            .with_ensure('present')
            .with_system(true)
            .with_shell('/sbin/nologin')
            .with_gid('rustion')
        }

        # Directories
        it { is_expected.to contain_file('/srv/application-config/rustion').with_ensure('directory').with_owner('rustion').with_group('rustion').with_mode('0750') }
        it { is_expected.to contain_file('/srv/application-config/rustion/audit-keys').with_ensure('directory').with_owner('root').with_group('rustion').with_mode('0750') }
        it { is_expected.to contain_file('/srv/application-config/rustion/users').with_ensure('directory').with_owner('rustion').with_group('rustion').with_mode('0750') }
        it { is_expected.to contain_file('/srv/application-config/rustion/targets').with_ensure('directory').with_owner('rustion').with_group('rustion').with_mode('0750') }
        it { is_expected.to contain_file('/srv/application-config/rustion/roles').with_ensure('directory').with_owner('rustion').with_group('rustion').with_mode('0750') }
        it { is_expected.to contain_file('/var/log/rustion').with_ensure('directory').with_owner('rustion').with_group('rustion') }
        it { is_expected.to contain_file('/var/log/rustion/audit').with_ensure('directory').with_owner('rustion').with_group('rustion') }
        it { is_expected.to contain_file('/srv/application-data/rustion').with_ensure('directory').with_owner('rustion').with_group('rustion') }
        it { is_expected.to contain_file('/srv/application-data/rustion/recordings').with_ensure('directory').with_owner('rustion').with_group('rustion') }
        it { is_expected.to contain_file('/var/run/rustion').with_ensure('directory').with_owner('rustion').with_group('rustion') }

        # Config file
        it {
          is_expected.to contain_file('/srv/application-config/rustion/rustion.toml')
            .with_ensure('file')
            .with_owner('root')
            .with_group('rustion')
            .with_mode('0640')
        }

        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{ssh_listen = "127\.0\.0\.1:2222"}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{cipher_suite = "hybrid-pqc"}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{mfa_required = true}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{\[crypto\]}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{\[audit\]}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{\[recording\]}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').without_content(%r{\[auth\.saml\]}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{ssh_host_key_path = "/srv/application-config/rustion/ssh_host_ed25519_key"}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{credential_key_path = "/srv/application-config/rustion/credential_key"}) }

        # Systemd unit file
        it { is_expected.to contain_file('/usr/lib/systemd/system/rustion.service').with_ensure('file').with_owner('root').with_mode('0644') }

        # Service
        it { is_expected.to contain_service('rustion').with_ensure('running').with_enable(true) }
      end

      context 'with manage_user => false' do
        let(:params) { { manage_user: false } }

        it { is_expected.to compile }
        it { is_expected.not_to contain_user('rustion') }
        it { is_expected.not_to contain_group('rustion') }
      end

      context 'with manage_service => false' do
        let(:params) { { manage_service: false } }

        it { is_expected.to compile }
        it { is_expected.not_to contain_service('rustion') }
      end

      context 'with saml_auth => true' do
        let(:params) do
          {
            saml_auth: true,
            saml_idp_metadata_url: 'https://idp.example.com/saml/metadata',
            saml_sp_entity_id: 'https://bastion.example.com/saml',
            saml_sp_acs_url: 'https://bastion.example.com/saml/acs',
          }
        end

        it { is_expected.to compile }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{\[auth\.saml\]}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{idp_metadata_url = "https://idp\.example\.com/saml/metadata"}) }
      end

      context 'with cipher_suite => classical' do
        let(:params) { { cipher_suite: 'classical' } }

        it { is_expected.to compile }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{cipher_suite = "classical"}) }
      end

      context 'with version => 0.7.16' do
        let(:params) { { version: '0.7.16' } }

        it { is_expected.to compile }
        it { is_expected.to contain_package('rustion-server').with_ensure('0.7.16') }
      end

      context 'with bastionvault_enabled => true (full)' do
        let(:params) do
          {
            bastionvault_enabled: true,
            bastionvault_listen: '0.0.0.0:9443',
            bastionvault_tls_cert_path: '/etc/rustion/control-plane/cert.pem',
            bastionvault_tls_key_path: '/etc/rustion/control-plane/key.pem',
            bastionvault_ssh_advertise: 'bastion.example.com:2222',
            bastionvault_rdp_advertise: 'bastion.example.com:3389',
            bastionvault_authorities: {
              'bastion-vault-prod' => {
                'name'              => 'bastion-vault-prod',
                'type'              => 'external-vault',
                'allowed_actions'   => ['open', 'renew', 'terminate'],
                'max_session_secs'  => 43_200,
              },
            },
          }
        end

        it { is_expected.to compile }
        it { is_expected.to contain_file('/srv/application-config/rustion/control-plane').with_ensure('directory').with_owner('rustion').with_group('rustion').with_mode('0750') }
        it { is_expected.to contain_file('/srv/application-config/rustion/authorities').with_ensure('directory').with_owner('rustion').with_group('rustion').with_mode('0750') }
        it { is_expected.to contain_file('/srv/application-config/rustion/authorities-pending').with_ensure('directory') }
        it { is_expected.to contain_file('/srv/application-config/rustion/tombstoned').with_ensure('directory') }
        # NOTE: per-authority YAML files use stdlib::to_yaml; not asserted here
        # because regent's mock interpreter skips the stdlib fixture.
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{\[control_plane\]}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{\nlisten = "0\.0\.0\.0:9443"}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{tls_cert_path = "/etc/rustion/control-plane/cert\.pem"}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{tls_key_path = "/etc/rustion/control-plane/key\.pem"}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{identity_dir = "/srv/application-config/rustion/control-plane"}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{authorities_dir = "/srv/application-config/rustion/authorities"}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{ssh_advertise = "bastion\.example\.com:2222"}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{rdp_advertise = "bastion\.example\.com:3389"}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{replay_window = 8192}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{telemetry_rate_capacity = 60}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{telemetry_rate_refill = 1}) }
        # Old keys / removed sub-tables must not appear (would fail rustion 0.9.0 parsing).
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').without_content(%r{\nbind =}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').without_content(%r{recording_fetch_enabled}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').without_content(%r{active_session_cap}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').without_content(%r{max_envelope_bytes}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').without_content(%r{\[control_plane\.health\]}) }
      end

      context 'with bastionvault_client_ca_path => set (mTLS)' do
        let(:params) do
          {
            bastionvault_enabled: true,
            bastionvault_tls_cert_path: '/etc/rustion/control-plane/cert.pem',
            bastionvault_tls_key_path: '/etc/rustion/control-plane/key.pem',
            bastionvault_client_ca_path: '/etc/rustion/control-plane/client-ca.pem',
          }
        end

        it { is_expected.to compile }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{client_ca_path = "/etc/rustion/control-plane/client-ca\.pem"}) }
      end

      context 'with bastionvault_client_ca_path => undef (default, no mTLS)' do
        let(:params) do
          {
            bastionvault_enabled: true,
            bastionvault_tls_cert_path: '/etc/rustion/control-plane/cert.pem',
            bastionvault_tls_key_path: '/etc/rustion/control-plane/key.pem',
          }
        end

        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').without_content(%r{client_ca_path}) }
      end

      context 'with bastionvault_enabled and no tls paths => self-signed' do
        let(:params) { { bastionvault_enabled: true } }

        it { is_expected.to compile }
        it { is_expected.to contain_exec('rustion-bv-tls-selfsigned').with_creates('/srv/application-config/rustion/control-plane/tls.crt') }
        it { is_expected.to contain_file('/srv/application-config/rustion/control-plane/tls.crt').with_mode('0644') }
        it { is_expected.to contain_file('/srv/application-config/rustion/control-plane/tls.key').with_mode('0640') }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{tls_cert_path = "/srv/application-config/rustion/control-plane/tls\.crt"}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{tls_key_path = "/srv/application-config/rustion/control-plane/tls\.key"}) }
      end

      context 'with bastionvault_enabled and bastionvault_manage_tls => false and no paths' do
        let(:params) do
          {
            bastionvault_enabled: true,
            bastionvault_manage_tls: false,
          }
        end

        it { is_expected.not_to compile }
      end

      context 'with bastionvault_enabled and explicit tls paths => self-sign at those paths' do
        let(:params) do
          {
            bastionvault_enabled: true,
            bastionvault_tls_cert_path: '/srv/application-config/rustion/tls/server.crt',
            bastionvault_tls_key_path: '/srv/application-config/rustion/tls/server.key',
          }
        end

        # Self-sign uses operator-provided paths; openssl creates parent dirs
        # so the cert lands wherever the operator put it. `creates =>` makes
        # the exec a no-op once a real cert is dropped in.
        it { is_expected.to contain_exec('rustion-bv-tls-selfsigned').with_creates('/srv/application-config/rustion/tls/server.crt') }
        it { is_expected.to contain_file('/srv/application-config/rustion/tls/server.crt') }
        it { is_expected.to contain_file('/srv/application-config/rustion/tls/server.key') }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{tls_cert_path = "/srv/application-config/rustion/tls/server\.crt"}) }
      end

      context 'with bastionvault_enabled and bastionvault_manage_tls => false and explicit paths' do
        let(:params) do
          {
            bastionvault_enabled: true,
            bastionvault_manage_tls: false,
            bastionvault_tls_cert_path: '/etc/rustion/control-plane/cert.pem',
            bastionvault_tls_key_path: '/etc/rustion/control-plane/key.pem',
          }
        end

        it { is_expected.not_to contain_exec('rustion-bv-tls-selfsigned') }
      end

      context 'with bastionvault_enabled => false (default)' do
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').without_content(%r{\[control_plane\]}) }
        # Authority dirs are managed regardless of bastionvault_enabled so
        # operators can stage pending enrolment YAMLs ahead of turning the
        # control plane on. The control-plane identity dir stays gated.
        it { is_expected.to contain_file('/srv/application-config/rustion/authorities').with_ensure('directory') }
        it { is_expected.to contain_file('/srv/application-config/rustion/authorities-pending').with_ensure('directory') }
        it { is_expected.to contain_file('/srv/application-config/rustion/authorities-pending/EXAMPLE.yaml.sample').with_ensure('file') }
        it { is_expected.not_to contain_file('/srv/application-config/rustion/control-plane') }
      end

      context 'with bastionvault_authorities_pending => hash (staged enrolment)' do
        let(:params) do
          {
            bastionvault_authorities_pending: {
              'bv-prod' => {
                'pubkey_ed25519_b64' => 'AAAA',
                'pubkey_mldsa65_b64' => 'BBBB',
                'deployment_id'      => 'deploy-1',
                'description'        => 'BV prod cluster',
                'submitted_at'       => '2026-05-21T12:00:00.000000Z',
              },
            },
          }
        end

        # Works even with bastionvault_enabled => false so YAMLs can be
        # staged before the control plane is turned on. Per-file resource
        # uses stdlib::to_yaml; not asserted here because regent's mock
        # interpreter skips the stdlib fixture (same as approved path).
        it { is_expected.to compile }
        it { is_expected.to contain_file('/srv/application-config/rustion/authorities-pending').with_ensure('directory') }
      end

      # NOTE: regent's mock interpreter only autoloads manifests/init.pp from
      # each module, so it can't see manifests/selinux.pp or its defined types.
      # We only assert what regent can verify here; the SELinux exec resources
      # themselves are covered by real-Puppet integration runs.
      context 'with manage_package => false' do
        let(:params) { { manage_package: false } }

        it { is_expected.to compile }
        it { is_expected.not_to contain_package('rustion-server') }
      end

      context 'with manage_repo => true on RedHat' do
        let(:params) do
          {
            manage_repo: true,
            repo_baseurl: 'https://repo.example.com/rustion/el9/',
            repo_gpgkey: 'https://repo.example.com/rustion/gpg.key',
          }
        end

        if os !~ /ubuntu|debian/
          it { is_expected.to compile }
          it { is_expected.to contain_yumrepo('rustion').with_baseurl('https://repo.example.com/rustion/el9/').with_gpgkey('https://repo.example.com/rustion/gpg.key').with_enabled('1') }
        end
      end

      context 'with manage_selinux => true' do
        let(:params) { { manage_selinux: true } }

        it { is_expected.to compile }
      end

      context 'with manage_selinux => false (default)' do
        it { is_expected.not_to contain_class('rustion::selinux') }
      end

      context 'with custom listen addresses' do
        let(:params) do
          {
            ssh_listen: '0.0.0.0:2222',
            rdp_listen: '0.0.0.0:3389',
            smb_listen: '0.0.0.0:4445',
          }
        end

        it { is_expected.to compile }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{ssh_listen = "0\.0\.0\.0:2222"}) }
        it { is_expected.to contain_file('/srv/application-config/rustion/rustion.toml').with_content(%r{rdp_listen = "0\.0\.0\.0:3389"}) }
      end
    end
  end
end
