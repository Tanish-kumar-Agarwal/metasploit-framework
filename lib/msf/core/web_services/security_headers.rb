# frozen_string_literal: true

require 'securerandom'

module Msf::WebServices
  # Adds defense-in-depth response headers to every web-service response.
  #
  # Inline scripts rendered by the service receive the per-request nonce from
  # +env['msf.csp_nonce']+. External sources are limited to the assets used by the
  # bundled API documentation, login page, and account page.
  class SecurityHeaders
    # Swagger UI injects inline styles, so style-src needs the compatibility exception.
    # Scripts remain nonce- or origin-restricted.
    CONTENT_SECURITY_POLICY = [
      "default-src 'none'",
      "base-uri 'none'",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "form-action 'self'",
      "connect-src 'self'",
      "img-src 'self' data:",
      'font-src https://fonts.gstatic.com',
      "style-src 'self' 'unsafe-inline' https://unpkg.com https://fonts.googleapis.com",
      "script-src 'self' 'nonce-%<nonce>s' https://unpkg.com https://code.jquery.com",
      "script-src-attr 'none'"
    ].join('; ').freeze

    REFERRER_POLICY = 'no-referrer'
    PERMISSIONS_POLICY = 'camera=(), geolocation=(), microphone=()'
    STRICT_TRANSPORT_SECURITY = 'max-age=31536000'

    # @param app [#call] the downstream Rack application.
    def initialize(app)
      @app = app
    end

    # @param env [Hash] the Rack request environment.
    # @return [Array] the Rack response.
    def call(env)
      nonce = SecureRandom.urlsafe_base64(32)
      env['msf.csp_nonce'] = nonce

      status, headers, body = @app.call(env)
      headers = headers.dup
      headers['content-security-policy'] = format(CONTENT_SECURITY_POLICY, nonce: nonce)
      headers['referrer-policy'] = REFERRER_POLICY
      headers['permissions-policy'] = PERMISSIONS_POLICY
      headers['x-content-type-options'] = 'nosniff'
      headers['x-frame-options'] = 'DENY'
      headers['strict-transport-security'] = STRICT_TRANSPORT_SECURITY if secure_request?(env)

      [status, headers, body]
    end

    private

    # Only the server-provided Rack scheme counts. Forwarded-protocol headers are not
    # trusted because this service has no trusted-proxy configuration.
    #
    # @param env [Hash] the Rack request environment.
    # @return [Boolean] true when the request reached Rack over HTTPS.
    def secure_request?(env)
      env['rack.url_scheme'] == 'https'
    end
  end
end
