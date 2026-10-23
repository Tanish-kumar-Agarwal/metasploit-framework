require 'fileutils'
require 'json'
require 'net/http'
require 'openssl'
require 'open3'
require 'rbconfig'
require 'spec_helper'
require 'tmpdir'
require 'uri'

RSpec.describe 'msfdb web service lifecycle' do
  before do
    skip 'Set MSFDB_INTEGRATION=true and use a disposable PostgreSQL environment to run this spec' unless ENV['MSFDB_INTEGRATION'] == 'true'
  end

  let(:framework_root) { File.expand_path('../..', __dir__) }
  let(:msfdb) { File.join(framework_root, 'msfdb') }
  let(:config_root) { Dir.mktmpdir('msfdb-integration') }
  # msfdb starts an external service, so do not let the RSpec process's test
  # environment make it use the unmigrated test database.
  let(:env) do
    {
      'MSF_CFGROOT_CONFIG' => config_root,
      'RAILS_ENV' => 'production',
      'RACK_ENV' => 'production'
    }
  end

  after do
    next unless ENV['MSFDB_INTEGRATION'] == 'true'

    Open3.capture3(env, RbConfig.ruby, msfdb, '--component', 'all', 'stop')
    FileUtils.remove_entry(config_root) if config_root && File.exist?(config_root)
  end

  it 'initializes the service, exposes readiness, and removes the setup token' do
    _stdout, stderr, status = Open3.capture3(env, RbConfig.ruby, msfdb, 'init', '--component', 'all', '--use-defaults')
    expect(status).to be_success, "msfdb init failed: #{stderr}"

    health_uri = URI('https://localhost:5443/api/v1/health')
    response = Net::HTTP.start(
      health_uri.host,
      health_uri.port,
      use_ssl: true,
      verify_mode: OpenSSL::SSL::VERIFY_NONE
    ) { |http| http.get(health_uri.request_uri) }

    expect(response.code).to eq('200')
    expect(JSON.parse(response.body).dig('data', 'status')).to eq('UP')
    expect(Dir.glob(File.join(config_root, 'msf-ws-setup-token-*'))).to be_empty
  end

  it 'does not silently reinitialize an already running service' do
    _stdout, stderr, status = Open3.capture3(env, RbConfig.ruby, msfdb, 'init', '--component', 'all', '--use-defaults')
    expect(status).to be_success, "msfdb init failed: #{stderr}"

    second_stdout, _second_stderr, second_status = Open3.capture3(
      env,
      RbConfig.ruby,
      msfdb,
      'init',
      '--component',
      'webservice',
      '--use-defaults'
    )

    expect(second_status).not_to be_success
    expect(second_stdout).to include('already running')
  end

  it 'reuses an existing administrator after a partial initialization' do
    credentials = ['--user', 'msfadmin', '--pass', 'integration_password']
    _stdout, stderr, status = Open3.capture3(
      env,
      RbConfig.ruby,
      msfdb,
      'init',
      '--component',
      'all',
      *credentials
    )
    expect(status).to be_success, "msfdb init failed: #{stderr}"

    _stdout, stderr, stop_status = Open3.capture3(
      env,
      RbConfig.ruby,
      msfdb,
      '--component',
      'webservice',
      'stop'
    )
    expect(stop_status).to be_success, "msfdb stop failed: #{stderr}"

    stdout, stderr, status = Open3.capture3(
      env,
      RbConfig.ruby,
      msfdb,
      'init',
      '--component',
      'webservice',
      *credentials
    )

    expect(status).to be_success, "msfdb reinit failed: #{stderr}"
    expect(stdout).to include('reusing the existing account')
  end
end
