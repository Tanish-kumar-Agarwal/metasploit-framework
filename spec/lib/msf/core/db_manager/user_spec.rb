require 'pg'
require 'spec_helper'

RSpec.describe Msf::DBManager::User do
  include_context 'Msf::DBManager'

  subject(:db) { db_manager }

  let(:attributes) do
    {
      username: 'bootstrap_admin',
      password: 'bootstrap_password',
      admin: false,
      persistence_token: 'attacker_token',
      sso_enabled: true
    }
  end

  before do
    Mdm::User.delete_all
  end

  describe '#report_initial_user' do
    it 'creates an admin user and ignores client-supplied privilege and token data' do
      user = db.report_initial_user(attributes)

      expect(user.admin).to be(true)
      expect(user.sso_enabled).to be(false)
      expect(user.persistence_token).not_to eq('attacker_token')
      expect(Mdm::User.where(username: attributes[:username])).to exist
    end

    it 'refuses to create a second initial user' do
      db.report_initial_user(attributes)

      expect do
        db.report_initial_user(attributes.merge(username: 'second_bootstrap_admin'))
      end.to raise_error(Msf::DBManager::User::InitialUserAlreadyExists)
    end

    it 'refuses to elevate an existing non-administrator' do
      existing_user = Mdm::User.create!(
        username: 'existing_user',
        crypted_password: BCrypt::Password.create('existing_password'),
        admin: false
      )

      expect do
        db.report_initial_user(attributes.merge(username: existing_user.username))
      end.to raise_error(Msf::DBManager::User::InitialUserAlreadyExists)

      expect(existing_user.reload.admin).to be(false)
    end

    it 'refuses to create an initial user while another bootstrap holds the lock' do
      allow(::ApplicationRecord.connection).to receive(:select_value).and_return(false)

      expect do
        db.report_initial_user(attributes)
      end.to raise_error(Msf::DBManager::User::InitialUserAlreadyExists, /already in progress/)
    end

    it 'refuses to create an initial user while another database connection holds the lock' do
      skip 'PostgreSQL advisory locks are required' unless ::ApplicationRecord.connection.adapter_name == 'PostgreSQL'

      db_config = ::ApplicationRecord.connection_db_config.configuration_hash.symbolize_keys
      pg_config = {
        host: db_config[:host] || 'localhost',
        port: db_config[:port] || 5432,
        dbname: db_config[:database],
        user: db_config[:username],
        password: db_config[:password]
      }
      lock_held = Queue.new
      release_lock = Queue.new
      holder = Thread.new do
        connection = PG.connect(**pg_config)
        begin
          connection.exec('BEGIN')
          connection.exec("SELECT pg_advisory_xact_lock(#{Msf::DBManager::User::INITIAL_USER_LOCK_KEY})")
          lock_held << :locked
          release_lock.pop
        ensure
          connection.exec('ROLLBACK')
          connection.close
        end
      rescue StandardError => e
        lock_held << e
      end

      begin
        result = lock_held.pop
        raise result if result.is_a?(Exception)

        expect do
          db.report_initial_user(attributes)
        end.to raise_error(Msf::DBManager::User::InitialUserAlreadyExists, /already in progress/)
      ensure
        release_lock << true
        holder.join
      end
    end

    it 'rolls back when creating the initial user fails' do
      allow(db).to receive(:report_user).and_raise(StandardError, 'insert failed')

      expect do
        db.report_initial_user(attributes)
      end.to raise_error(StandardError, /insert failed/)

      expect(Mdm::User.count).to eq(0)
    end
  end
end
