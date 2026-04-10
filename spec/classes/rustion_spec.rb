require 'spec_helper'

describe 'rustion' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      context 'with default parameters' do
        it { is_expected.to compile }

        # Package
        it { is_expected.to contain_package('rustion').with_ensure('present') }

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
        it { is_expected.to contain_file('/opt/rustion').with_ensure('directory').with_owner('rustion').with_group('rustion').with_mode('0755') }
        it { is_expected.to contain_file('/opt/rustion/audit-keys').with_ensure('directory').with_owner('root').with_group('rustion').with_mode('0750') }
        it { is_expected.to contain_file('/opt/rustion/users').with_ensure('directory').with_owner('rustion').with_group('rustion').with_mode('0750') }
        it { is_expected.to contain_file('/opt/rustion/targets').with_ensure('directory').with_owner('rustion').with_group('rustion').with_mode('0750') }
        it { is_expected.to contain_file('/opt/rustion/roles').with_ensure('directory').with_owner('rustion').with_group('rustion').with_mode('0750') }
        it { is_expected.to contain_file('/var/log/rustion').with_ensure('directory').with_owner('rustion').with_group('rustion') }
        it { is_expected.to contain_file('/var/log/rustion/audit').with_ensure('directory').with_owner('rustion').with_group('rustion') }
        it { is_expected.to contain_file('/var/lib/rustion').with_ensure('directory').with_owner('rustion').with_group('rustion') }
        it { is_expected.to contain_file('/var/lib/rustion/recordings').with_ensure('directory').with_owner('rustion').with_group('rustion') }
        it { is_expected.to contain_file('/var/run/rustion').with_ensure('directory').with_owner('rustion').with_group('rustion') }

        # Config file
        it {
          is_expected.to contain_file('/opt/rustion/rustion.toml')
            .with_ensure('file')
            .with_owner('root')
            .with_group('rustion')
            .with_mode('0640')
        }

        it { is_expected.to contain_file('/opt/rustion/rustion.toml').with_content(%r{ssh_listen = "127\.0\.0\.1:2222"}) }
        it { is_expected.to contain_file('/opt/rustion/rustion.toml').with_content(%r{cipher_suite = "hybrid-pqc"}) }
        it { is_expected.to contain_file('/opt/rustion/rustion.toml').with_content(%r{mfa_required = true}) }
        it { is_expected.to contain_file('/opt/rustion/rustion.toml').with_content(%r{\[crypto\]}) }
        it { is_expected.to contain_file('/opt/rustion/rustion.toml').with_content(%r{\[audit\]}) }
        it { is_expected.to contain_file('/opt/rustion/rustion.toml').with_content(%r{\[recording\]}) }
        it { is_expected.to contain_file('/opt/rustion/rustion.toml').without_content(%r{\[auth\.saml\]}) }

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
        it { is_expected.to contain_file('/opt/rustion/rustion.toml').with_content(%r{\[auth\.saml\]}) }
        it { is_expected.to contain_file('/opt/rustion/rustion.toml').with_content(%r{idp_metadata_url = "https://idp\.example\.com/saml/metadata"}) }
      end

      context 'with cipher_suite => classical' do
        let(:params) { { cipher_suite: 'classical' } }

        it { is_expected.to compile }
        it { is_expected.to contain_file('/opt/rustion/rustion.toml').with_content(%r{cipher_suite = "classical"}) }
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
        it { is_expected.to contain_file('/opt/rustion/rustion.toml').with_content(%r{ssh_listen = "0\.0\.0\.0:2222"}) }
        it { is_expected.to contain_file('/opt/rustion/rustion.toml').with_content(%r{rdp_listen = "0\.0\.0\.0:3389"}) }
      end
    end
  end
end
