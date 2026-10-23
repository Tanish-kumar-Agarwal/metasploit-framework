# frozen_string_literal: true

# Unauthenticated database readiness endpoint for the web service.
module Msf::WebServices::ReadinessServlet
  # The data service has no Msf::Framework, so it cannot use Msf::RPC::Health.
  def self.api_path
    '/api/v1/health'
  end

  def self.registered(app)
    app.get api_path, &readiness
  end

  def self.readiness
    lambda {
      healthy = begin
        get_db.users({}).count
        true
      rescue StandardError => e
        warn("MSF web service readiness check failed: #{e.message}")
        false
      end

      set_json_data_response(
        response: { status: healthy ? 'UP' : 'DOWN' },
        code: healthy ? 200 : 503
      )
    }
  end
  private_class_method :readiness
end
