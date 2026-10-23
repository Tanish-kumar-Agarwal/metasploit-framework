require 'spec_helper'
require 'tmpdir'

RSpec.describe 'msfdb web service helpers' do
  before(:all) do
    load File.expand_path('../../msfdb', __dir__)
  end

  let(:cli) do
    Object.new.tap do |instance|
      instance.instance_variable_set(:@options, options)
      instance.instance_variable_set(:@msf_ws_user, 'msfadmin')
      instance.instance_variable_set(:@msf_ws_pass, 'password')
      instance.instance_variable_set(:@ws_api_token, nil)
      instance.instance_variable_set(:@ws_generated_ssl, false)
      instance.instance_variable_set(:@ws_started_by_this_run, false)
      allow(instance).to receive(:puts)
      allow(instance).to receive(:print_error)
      allow(instance).to receive(:print_web_service_credentials)
      allow(instance).to receive(:print_web_service_api_token)
    end
  end

  let(:options) do
    {
      address: 'localhost',
      debug: false,
      delete_existing_data: false,
      port: 5443,
      retry_delay: 0,
      retry_max: 0,
      ssl: false,
      ssl_cert: nil,
      ssl_disable_verify: false,
      ssl_key: nil,
      use_defaults: true
    }
  end

  describe '#add_web_service_user' do
    it 'refuses to reuse an existing account that is not an administrator' do
      allow(cli).to receive(:http_request).and_return(
        { response: { error: { code: 409, message: 'An initial user already exists' } } },
        { response: { data: { token: 'nonadmin-token' } } },
        { response: { error: { code: 403, message: 'Invalid permissions.' } } }
      )

      expect(cli.send(:add_web_service_user)).to be(false)
      expect(cli).to have_received(:print_error).with(/could not be verified as an administrator/)
      expect(cli).not_to have_received(:print_web_service_credentials)
      expect(cli).not_to have_received(:print_web_service_api_token)
    end

    it 'reuses an existing administrator after a partial initialization' do
      allow(cli).to receive(:http_request).and_return(
        { response: { error: { code: 409, message: 'An initial user already exists' } } },
        { response: { data: { token: 'admin-token' } } },
        { response: { data: [{ username: 'msfadmin', admin: true }] } }
      )

      expect(cli.send(:add_web_service_user)).to be(true)
      expect(cli).to have_received(:print_web_service_credentials)
      expect(cli).to have_received(:print_web_service_api_token)
    end
  end

  describe '#remove_web_service_setup_token' do
    it 'clears the token state after successful deletion' do
      Dir.mktmpdir do |dir|
        path = File.join(dir, 'setup-token')
        File.write(path, 'token')
        cli.instance_variable_set(:@ws_setup_token_file, path)
        cli.instance_variable_set(:@ws_setup_token, 'token')

        expect(cli.send(:remove_web_service_setup_token)).to be(true)
        expect(cli.instance_variable_get(:@ws_setup_token_file)).to be_nil
        expect(cli.instance_variable_get(:@ws_setup_token)).to be_nil
        expect(File.exist?(path)).to be(false)
      end
    end

    it 'keeps the token state and reports failure when deletion fails' do
      Dir.mktmpdir do |dir|
        path = File.join(dir, 'setup-token')
        File.write(path, 'token')
        cli.instance_variable_set(:@ws_setup_token_file, path)
        cli.instance_variable_set(:@ws_setup_token, 'token')
        allow(File).to receive(:delete).and_wrap_original do |original, target|
          raise Errno::EACCES, target if target == path

          original.call(target)
        end

        expect(cli.send(:remove_web_service_setup_token)).to be(false)
        expect(cli.instance_variable_get(:@ws_setup_token_file)).to eq(path)
        expect(cli.instance_variable_get(:@ws_setup_token)).to eq('token')
        expect(cli).to have_received(:print_error).with(/Failed to remove/)
      end
    end
  end

  describe '#init_web_service' do
    it 'fails closed and stops the service when the setup token cannot be removed' do
      token_path = File.expand_path('msf-ws-setup-token')
      allow(cli).to receive(:web_service_pid_status).and_return(WebServicePIDStatus::NO_PID_FILE)
      allow(cli).to receive(:should_generate_web_service_ssl).and_return(false)
      allow(cli).to receive(:create_web_service_setup_token) do
        cli.instance_variable_set(:@ws_setup_token_file, token_path)
        cli.instance_variable_set(:@ws_setup_token, 'token')
        true
      end
      allow(cli).to receive(:start_web_service).with(expect_auth: false) do
        cli.instance_variable_set(:@ws_started_by_this_run, true)
        true
      end
      allow(cli).to receive(:add_web_service_user).and_return(true)
      allow(cli).to receive(:remove_web_service_setup_token).and_return(false)
      allow(cli).to receive(:stop_web_service)
      expect(cli).not_to receive(:add_web_service_workspace)

      expect(cli.send(:init_web_service)).to be(false)
      expect(cli).to have_received(:stop_web_service).once
      expect(cli.instance_variable_get(:@ws_setup_token_file)).to eq(token_path)
    end

    it 'recovers on a later run after the stale setup token file is removed' do
      Dir.mktmpdir do |dir|
        cli.instance_variable_set(:@localconf, dir)
        cli.instance_variable_set(:@ws_tag, 'msf-ws')
        allow(cli).to receive(:web_service_pid_status).and_return(WebServicePIDStatus::NO_PID_FILE)
        allow(cli).to receive(:should_generate_web_service_ssl).and_return(false)
        allow(cli).to receive(:start_web_service).with(expect_auth: false) do
          cli.instance_variable_set(:@ws_started_by_this_run, true)
          true
        end
        allow(cli).to receive(:add_web_service_user).and_return(true)
        allow(cli).to receive(:add_web_service_workspace).and_return(true)
        allow(cli).to receive(:output_web_service_information)
        allow(cli).to receive(:stop_web_service)
        remove_attempts = 0
        allow(cli).to receive(:remove_web_service_setup_token).and_wrap_original do |original|
          remove_attempts += 1
          remove_attempts <= 2 ? false : original.call
        end

        expect(cli.send(:init_web_service)).to be(false)
        stale_path = cli.instance_variable_get(:@ws_setup_token_file)
        expect(File.exist?(stale_path)).to be(true)
        expect(cli).to have_received(:stop_web_service).once

        File.delete(stale_path)

        expect(cli.send(:init_web_service)).to be(true)
        expect(cli.instance_variable_get(:@ws_setup_token_file)).to be_nil
        expect(Dir.glob(File.join(dir, 'msf-ws-setup-token-*'))).to be_empty
      end
    end
  end

  describe '#start_web_service_daemon' do
    it 'passes the setup token file to the daemon environment' do
      token_path = File.expand_path('msf-ws-setup-token')
      driver = double('database driver')
      allow(cli).to receive(:thin_cmd).and_return('thin')
      allow(cli).to receive(:web_service_online_check).and_return({ state: :online })
      allow(cli).to receive(:stop_web_service)
      allow(cli).to receive(:web_service_pid).and_return(nil)
      cli.instance_variable_set(:@db_driver, driver)
      cli.instance_variable_set(:@ws_setup_token_file, token_path)
      cli.instance_variable_set(:@ws_log, '/tmp/msf-ws.log')

      expect(driver).to receive(:run_cmd)
        .with('thin start', env: { 'MSF_WS_SETUP_TOKEN_FILE' => token_path })
        .and_return(0)

      expect(cli.send(:start_web_service_daemon, expect_auth: false)).to be(true)
      expect(cli.instance_variable_get(:@ws_started_by_this_run)).to be(true)
    end
  end
end
