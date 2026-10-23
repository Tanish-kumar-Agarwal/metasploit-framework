require 'securerandom'

module Msf::DBManager::User

  MIN_TOKEN_LENGTH = 20

  # Key used to serialize first-user bootstrap across web service processes.
  INITIAL_USER_LOCK_KEY = 0x4d5346424f4f54

  # Attributes that an unauthenticated bootstrap may set. Privilege and persistence fields
  # are deliberately excluded so the bootstrap can only create an administrator with a
  # password, never an account with a caller-selected role or authentication bypass.
  INITIAL_USER_ATTRIBUTES = %w[username password fullname email phone company prefs].freeze

  # Raised when the initial user has already been created or another process is creating it.
  class InitialUserAlreadyExists < StandardError; end

  # Returns a list of all users in the database
  def users(opts)
    ::ApplicationRecord.connection_pool.with_connection {

      opts = opts.clone() # protect the original caller's opts
      search_term = opts.delete(:search_term)
      if search_term && !search_term.empty?
        column_search_conditions = Msf::Util::DBManager.create_all_column_search_conditions(Mdm::User, search_term)
        Mdm::User.where(opts).where(column_search_conditions)
      else
        Mdm::User.where(opts)
      end
    }
  end

  #
  # Report a user's attributes.
  #
  # The opts parameter MUST contain:
  # +:username+:: -- the username
  # +:password+:: -- the users's cleartext password
  #
  # The opts parameter can contain:
  # +:fullname+:: -- the users's fullname
  # +:email+::    -- the users's email
  # +:phone+::    -- the users's phone
  # +:email+::    -- the users's email
  # +:company+::  -- the users's company
  # +:prefs+::    -- [Hash] the users's preferences
  # +:admin+::    -- [Boolean] True if the user is an admin; otherwise, false.
  #
  # @return [Mdm::User] The reported Mdm::User object.
  def report_user(opts)
    return unless active
    raise ArgumentError.new("Missing required option :username") if opts[:username].nil?
    raise ArgumentError.new("Missing required option :password") if opts[:password].nil?

    ::ApplicationRecord.connection_pool.with_connection {

      conditions = {username: opts[:username]}
      user = Mdm::User.where(conditions).first_or_initialize

      opts.each do |k,v|
        if user.attribute_names.include?(k.to_s)
          user[k] = v
        elsif !v.blank?
          dlog("Unknown attribute for ::Mdm::User: #{k}")
        end
      end

      user.crypted_password = BCrypt::Password.create(opts[:password])
      user.admin = false if opts[:admin].nil?

      # Finalize
      if user.changed?
        msf_assign_timestamps(opts, user)
        user.save!
      end

      user
    }
  end

  # Creates the first web service user as an administrator.
  #
  # The caller must have already verified the one-time setup token. This method serializes
  # bootstrap across processes, rechecks the users table inside the transaction, and forces
  # administrator privileges so client-supplied bootstrap data cannot choose its own role
  # or persistence token.
  #
  # @param opts [Hash] user attributes; must include :username and :password.
  # @return [Mdm::User] the created administrator.
  # @raise [ArgumentError] if :username or :password is missing.
  # @raise [InitialUserAlreadyExists] if a user exists or another bootstrap is in progress.
  def report_initial_user(opts)
    raise Rex::RuntimeError, 'Database is not active' unless active
    raise ArgumentError, 'Missing required option :username' if opts[:username].nil?
    raise ArgumentError, 'Missing required option :password' if opts[:password].nil?

    ::ApplicationRecord.transaction do
      lock_acquired = ::ApplicationRecord.connection.select_value(
        "SELECT pg_try_advisory_xact_lock(#{INITIAL_USER_LOCK_KEY})"
      )
      unless [true, 't', 'true', '1', 1].include?(lock_acquired)
        raise InitialUserAlreadyExists, 'Initial user creation is already in progress'
      end
      raise InitialUserAlreadyExists, 'An initial user already exists' if Mdm::User.exists?

      initial_user_opts = opts.each_with_object({}) do |(key, value), allowed|
        allowed[key.to_s.to_sym] = value if INITIAL_USER_ATTRIBUTES.include?(key.to_s)
      end
      initial_user_opts[:admin] = true
      user = report_user(initial_user_opts)
      raise Rex::RuntimeError, 'Failed to create the initial user' if user.nil?

      user
    end
  end

  # Update the attributes of a user entry with the values in opts.
  # The values in opts should match the attributes to update.
  #
  # @param opts [Hash] Hash containing the updated values. Key should match the attribute to update. Must contain :id of record to update.
  # @return [Mdm::User] The updated Mdm::User object.
  def update_user(opts)
    ::ApplicationRecord.connection_pool.with_connection {
      opts = opts.clone() # protect the original caller's opts
      id = opts.delete(:id)
      user = Mdm::User.find(id)
      user.update!(opts)
      return user
    }
  end

  # Deletes user entries based on the IDs passed in.
  #
  # @param opts[:ids] [Array] Array containing Integers corresponding to the IDs of the user entries to delete.
  # @return [Array] Array containing the Mdm::User objects that were successfully deleted.
  def delete_user(opts)
    raise ArgumentError.new("The following options are required: :ids") if opts[:ids].nil?

    ::ApplicationRecord.connection_pool.with_connection {
      deleted = []
      opts[:ids].each do |user_id|
        user = Mdm::User.find(user_id)
        begin
          deleted << user.destroy
        rescue # refs suck
          elog("Forcibly deleting #{user}")
          deleted << user.delete
        end
      end

      return deleted
    }
  end

  # Authenticates the user.
  #
  # @param opts [Hash] Options hash.
  # @option opts [Integer] :id ID of the user to authenticate.
  # @option opts [String] :password The user's password.
  # @return [Boolean] True if the user is successfully authenticated; otherwise, false.
  def authenticate_user(opts)
    raise ArgumentError.new("The following options are required: :id") if opts[:id].nil?
    raise ArgumentError.new("The following options are required: :password") if opts[:password].nil?

    user = Mdm::User.find(opts[:id])
    begin
      !user.nil? && BCrypt::Password.new(user.crypted_password) == opts[:password]
    rescue BCrypt::Errors::InvalidHash
      false
    end
  end

  # Creates a new API token for the user.
  #
  # @param opts [Hash] Options hash.
  # @option opts [Integer] :id ID for the user (required).
  # @option opts [Integer] :token_length Token length (optional).
  #
  # @return [String] The new API token.
  def create_new_user_token(opts)
    raise ArgumentError.new("The following options are required: :id") if opts[:id].nil?

    token_length = opts[:token_length] || MIN_TOKEN_LENGTH
    # NOTE: repurposing persistence_token in the database as the API token
    user = Mdm::User.find(opts[:id])
    user.update!({persistence_token: SecureRandom.hex(token_length)})
    user.persistence_token
  end

end
