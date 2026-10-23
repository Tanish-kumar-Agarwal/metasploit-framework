require 'securerandom'
require 'tmpdir'
require 'spec_helper'
require 'rack/test'

RSpec.describe Msf::WebServices::MetasploitApiApp do
  include Rack::Test::Methods
  include_context 'Msf::DBManager'

  let(:app) { described_class.new }
  let(:setup_token) { SecureRandom.hex(32) }

  around do |example|
    described_class.set :setup_token, setup_token
    example.run
  ensure
    described_class.set :setup_token, nil
  end

  before(:example) do
    header 'Content-Type', 'application/json'
    # Create a user so authentication is enforced for the general API tests.
    Mdm::User.where(username: 'test_user').first_or_create!(
      crypted_password: BCrypt::Password.create('test_password'),
      admin: false
    )
  end

  describe 'host authorization' do
    it 'does not reject requests with a 403 Host not permitted error' do
      get '/api/v1/hosts'
      expect(last_response.status).not_to eq(403)
      expect(last_response.body).not_to include('Host not permitted')
    end
  end

  describe 'authentication' do
    it 'returns 401 for unauthenticated requests to protected endpoints' do
      get '/api/v1/hosts'
      expect(last_response.status).to eq(401)
    end

    it 'returns a JSON error body for unauthenticated requests' do
      get '/api/v1/hosts'
      json = JSON.parse(last_response.body)
      expect(json).to have_key('error')
      expect(json['error']['message']).to include('Authenticate to access this resource')
    end
  end

  describe 'user management authorization' do
    let(:admin_token) { SecureRandom.hex(32) }
    let(:non_admin_token) { SecureRandom.hex(32) }

    before do
      Mdm::User.where(username: 'admin_user').first_or_create!(
        crypted_password: BCrypt::Password.create('admin_password'),
        admin: true,
        persistence_token: admin_token
      )
      Mdm::User.where(username: 'non_admin_user').first_or_create!(
        crypted_password: BCrypt::Password.create('non_admin_password'),
        admin: false,
        persistence_token: non_admin_token
      )
    end

    def authorization_headers(token)
      {
        'CONTENT_TYPE' => 'application/json',
        'HTTP_AUTHORIZATION' => "Bearer #{token}"
      }
    end

    it 'allows an authenticated administrator to create a non-administrator' do
      post '/api/v1/users',
           { username: 'created_user', password: 'created_password', admin: false }.to_json,
           authorization_headers(admin_token)

      expect(last_response.status).to eq(200)
      user = Mdm::User.find_by(username: 'created_user')
      expect(user).to be_present
      expect(user.admin).to be(false)
    end

    it 'rejects a non-administrator attempting to create an administrator' do
      post '/api/v1/users',
           { username: 'forbidden_admin', password: 'forbidden_password', admin: true }.to_json,
           authorization_headers(non_admin_token)

      expect(last_response.status).to eq(403)
      expect(Mdm::User.where(username: 'forbidden_admin')).to be_empty
    end
  end

  describe 'initial account bootstrap' do
    # msfdb creates the first web service user by POSTing to /api/v1/users before any
    # credentials exist. The request must also carry the one-time setup token written by
    # msfdb, so an empty users table alone can never expose the bootstrap route.
    before do
      Mdm::User.delete_all
      # The app latches this on for the lifetime of the process, so reset it here.
      @original_auth_initialized = described_class.auth_initialized
      described_class.auth_initialized = false
    end

    after do
      described_class.auth_initialized = @original_auth_initialized
    end

    def bootstrap_headers(token)
      {
        'CONTENT_TYPE' => 'application/json',
        'HTTP_X_MSF_SETUP_TOKEN' => token
      }
    end

    it 'rejects the initial account without a setup token' do
      post '/api/v1/users', { username: 'bootstrap_user', password: 'bootstrap_password' }.to_json

      expect(last_response.status).to eq(401)
      expect(Mdm::User.count).to eq(0)
    end

    it 'rejects the initial account with an invalid setup token' do
      post '/api/v1/users', { username: 'bootstrap_user', password: 'bootstrap_password' }.to_json,
           bootstrap_headers(SecureRandom.hex(32))

      expect(last_response.status).to eq(401)
      expect(Mdm::User.count).to eq(0)
    end

    it 'allows the initial account with a valid setup token' do
      post '/api/v1/users', { username: 'bootstrap_user', password: 'bootstrap_password' }.to_json,
           bootstrap_headers(setup_token)

      expect(last_response.status).to eq(200)
      expect(Mdm::User.find_by(username: 'bootstrap_user')).to be_present
    end

    it 'forces the initial account to be an admin and ignores a submitted persistence token' do
      post '/api/v1/users',
           { username: 'bootstrap_user', password: 'bootstrap_password', admin: false, persistence_token: 'attacker_token', sso_enabled: true }.to_json,
           bootstrap_headers(setup_token)

      expect(last_response.status).to eq(200)
      user = Mdm::User.find_by(username: 'bootstrap_user')
      expect(user.admin).to be(true)
      expect(user.sso_enabled).to be(false)
      expect(user.persistence_token).not_to eq('attacker_token')
    end

    it 'does not allow the setup token to create another account after bootstrap' do
      post '/api/v1/users', { username: 'bootstrap_user', password: 'bootstrap_password' }.to_json,
           bootstrap_headers(setup_token)
      expect(last_response.status).to eq(200)

      post '/api/v1/users', { username: 'second_user', password: 'second_password' }.to_json,
           bootstrap_headers(setup_token)

      expect(last_response.status).to eq(401)
      expect(Mdm::User.where(username: 'second_user')).to be_empty
    end

    it 'clears the in-memory setup token after bootstrap' do
      post '/api/v1/users', { username: 'bootstrap_user', password: 'bootstrap_password' }.to_json,
           bootstrap_headers(setup_token)

      expect(last_response.status).to eq(200)
      expect(described_class.settings.setup_token).to be_nil
    end

    it 'rejects bootstrap with a stale process latch when an account already exists' do
      post '/api/v1/users', { username: 'bootstrap_user', password: 'bootstrap_password' }.to_json,
           bootstrap_headers(setup_token)
      expect(last_response.status).to eq(200)

      # Simulate a new or racing worker that has not observed the process latch.
      described_class.auth_initialized = false
      described_class.set :setup_token, setup_token

      post '/api/v1/users', { username: 'second_user', password: 'second_password' }.to_json,
           bootstrap_headers(setup_token)

      expect(last_response.status).to eq(401)
      expect(Mdm::User.where(username: 'second_user')).to be_empty
    end

    it 'does not latch authentication initialization when initial user creation fails' do
      db = instance_double(Msf::DBManager, users: [], report_initial_user: nil)
      allow(db).to receive(:report_initial_user).and_raise(StandardError, 'database failure')
      allow_any_instance_of(described_class).to receive(:get_db).and_return(db)

      post '/api/v1/users', { username: 'bootstrap_user', password: 'bootstrap_password' }.to_json,
           bootstrap_headers(setup_token)

      expect(last_response.status).to eq(500)
      expect(Mdm::User.count).to eq(0)
      expect(described_class.auth_initialized).to be(false)
    end

    it 'returns a conflict when another bootstrap already created the initial user' do
      db = instance_double(Msf::DBManager, users: [], report_initial_user: nil)
      allow(db).to receive(:report_initial_user)
        .and_raise(Msf::DBManager::User::InitialUserAlreadyExists, 'An initial user already exists')
      allow_any_instance_of(described_class).to receive(:get_db).and_return(db)

      post '/api/v1/users', { username: 'bootstrap_user', password: 'bootstrap_password' }.to_json,
           bootstrap_headers(setup_token)

      expect(last_response.status).to eq(409)
      expect(Mdm::User.count).to eq(0)
    end

    # The exemption exists only so that msfdb can create the first account. Anything else
    # must still be authenticated, otherwise an unexpectedly empty users table - a restored
    # blank database, a failover onto a fresh instance - exposes the whole API.
    it 'still requires authentication for other endpoints while no users exist' do
      get '/api/v1/hosts', {}, { 'HTTP_X_MSF_SETUP_TOKEN' => setup_token }
      expect(last_response.status).to eq(401)
    end

    it 'still requires authentication to list users while no users exist' do
      get '/api/v1/users', {}, { 'HTTP_X_MSF_SETUP_TOKEN' => setup_token }
      expect(last_response.status).to eq(401)
    end

    it 'keeps readiness available while bootstrap is pending' do
      get '/api/v1/health'

      expect(last_response.status).to eq(200)
      expect(JSON.parse(last_response.body)).to eq({ 'data' => { 'status' => 'UP' } })
    end
  end

  describe 'readiness' do
    it 'is available without authentication once authentication is initialized' do
      get '/api/v1/health'

      expect(last_response.status).to eq(200)
      expect(JSON.parse(last_response.body)).to eq({ 'data' => { 'status' => 'UP' } })
    end

    it 'returns 503 when the database is unavailable' do
      allow_any_instance_of(described_class).to receive(:get_db).and_raise(StandardError, 'database unavailable')

      get '/api/v1/health'

      expect(last_response.status).to eq(503)
      expect(JSON.parse(last_response.body)).to eq({ 'data' => { 'status' => 'DOWN' } })
    end
  end

  describe '.load_setup_token' do
    around do |example|
      original_file = ENV['MSF_WS_SETUP_TOKEN_FILE']
      original_token = ENV['MSF_WS_SETUP_TOKEN']
      example.run
    ensure
      ENV['MSF_WS_SETUP_TOKEN_FILE'] = original_file
      ENV['MSF_WS_SETUP_TOKEN'] = original_token
    end

    it 'loads a 0600 regular file containing a 64-character hex token' do
      Dir.mktmpdir do |dir|
        path = File.join(dir, 'setup-token')
        File.write(path, setup_token)
        File.chmod(0o600, path) unless Gem.win_platform?
        ENV['MSF_WS_SETUP_TOKEN_FILE'] = path

        expect(described_class.load_setup_token).to eq(setup_token)
      end
    end

    it 'does not fall back to the MSF_WS_SETUP_TOKEN environment variable' do
      ENV.delete('MSF_WS_SETUP_TOKEN_FILE')
      ENV['MSF_WS_SETUP_TOKEN'] = setup_token

      expect(described_class.load_setup_token).to be_nil
    end

    it 'rejects a relative token file path' do
      ENV['MSF_WS_SETUP_TOKEN_FILE'] = 'setup-token'

      expect(described_class.load_setup_token).to be_nil
    end

    it 'rejects a token file that is not private' do
      skip 'POSIX file modes are not enforced on Windows' if Gem.win_platform?

      Dir.mktmpdir do |dir|
        path = File.join(dir, 'setup-token')
        File.write(path, setup_token)
        File.chmod(0o644, path)
        ENV['MSF_WS_SETUP_TOKEN_FILE'] = path

        expect(described_class.load_setup_token).to be_nil
      end
    end

    it 'rejects a symlinked token file' do
      skip 'Symbolic link creation is not reliably available on Windows' if Gem.win_platform?

      Dir.mktmpdir do |dir|
        target = File.join(dir, 'setup-token')
        link = File.join(dir, 'setup-token-link')
        File.write(target, setup_token)
        File.chmod(0o600, target)
        File.symlink(target, link)
        ENV['MSF_WS_SETUP_TOKEN_FILE'] = link

        expect(described_class.load_setup_token).to be_nil
      end
    end

    it 'rejects a token file replaced between validation and opening' do
      Dir.mktmpdir do |dir|
        path = File.join(dir, 'setup-token')
        replacement = File.join(dir, 'setup-token-replacement')
        File.write(path, setup_token)
        File.write(replacement, SecureRandom.hex(32))
        File.chmod(0o600, path) unless Gem.win_platform?
        File.chmod(0o600, replacement) unless Gem.win_platform?
        ENV['MSF_WS_SETUP_TOKEN_FILE'] = path

        replaced = false
        allow(File).to receive(:open).and_wrap_original do |original, *args, &block|
          unless replaced
            replaced = true
            File.delete(path)
            File.rename(replacement, path)
          end
          original.call(*args, &block)
        end

        expect(described_class.load_setup_token).to be_nil
      end
    end
  end

  describe 'response headers' do
    it 'uses lowercase header keys' do
      get '/api/v1/hosts'
      raw_keys = last_response.headers.keys
      raw_keys.each do |key|
        expect(key).to eq(key.downcase), "Expected header '#{key}' to be lowercase"
      end
    end
  end
end
