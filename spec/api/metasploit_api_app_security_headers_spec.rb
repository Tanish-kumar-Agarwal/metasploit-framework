require 'spec_helper'
require 'rack/test'

RSpec.describe Msf::WebServices::MetasploitApiApp, 'security headers' do
  include Rack::Test::Methods
  include_context 'Msf::DBManager'

  let(:app) { described_class.new }

  before do
    header 'Content-Type', 'application/json'
    Mdm::User.where(username: 'test_user').first_or_create!(
      crypted_password: BCrypt::Password.create('test_password'),
      admin: false
    )
  end

  it 'uses lowercase header keys' do
    get '/api/v1/hosts'

    last_response.headers.each_key do |key|
      expect(key).to eq(key.downcase), "Expected header '#{key}' to be lowercase"
    end
  end

  it 'sets hardened security headers on JSON responses' do
    get '/api/v1/hosts'

    headers = last_response.headers
    expect(headers['content-security-policy']).to be_present
    expect(headers['referrer-policy']).to eq('no-referrer')
    expect(headers['permissions-policy']).to eq('camera=(), geolocation=(), microphone=()')
    expect(headers['x-content-type-options']).to eq('nosniff')
    expect(headers['x-frame-options']).to eq('DENY')
    expect(headers).not_to have_key('strict-transport-security')
  end

  it 'uses a nonce-restricted CSP with only the required browser origins' do
    get '/api/v1/hosts'

    directives = last_response.headers['content-security-policy'].split(';').map(&:strip).to_h do |directive|
      directive.split(' ', 2)
    end

    expect(directives['default-src']).to eq("'none'")
    expect(directives['base-uri']).to eq("'none'")
    expect(directives['object-src']).to eq("'none'")
    expect(directives['frame-ancestors']).to eq("'none'")
    expect(directives['form-action']).to eq("'self'")
    expect(directives['connect-src']).to eq("'self'")
    expect(directives['img-src']).to eq("'self' data:")
    expect(directives['font-src']).to eq('https://fonts.gstatic.com')
    expect(directives['style-src']).to eq("'self' 'unsafe-inline' https://unpkg.com https://fonts.googleapis.com")
    expect(directives['script-src']).to include("'self' 'nonce-")
    expect(directives['script-src']).to include('https://unpkg.com')
    expect(directives['script-src']).to include('https://code.jquery.com')
    expect(directives['script-src']).not_to include("'unsafe-inline'")
    expect(directives['script-src-attr']).to eq("'none'")
  end

  it 'uses one nonce for the CSP and every inline script on HTML pages' do
    ['/api/v1/api-docs', '/api/v1/auth/login', '/api/v1/auth/account'].each do |path|
      get path

      expect(last_response.status).to eq(200), "Expected #{path} to render successfully"
      nonce = last_response.headers['content-security-policy'][/'nonce-([^']+)'/, 1]
      expect(nonce).to be_present

      script_tags = last_response.body.scan(/<script\b[^>]*>/i)
      inline_scripts = script_tags.reject { |tag| tag.match?(/\bsrc=/) }
      expect(inline_scripts).not_to be_empty
      expect(inline_scripts).to all(include(%(nonce="#{nonce}")))
    end
  end

  it 'generates a distinct nonce for each response' do
    get '/api/v1/auth/login'
    first_nonce = last_response.headers['content-security-policy'][/'nonce-([^']+)'/, 1]

    get '/api/v1/auth/login'
    second_nonce = last_response.headers['content-security-policy'][/'nonce-([^']+)'/, 1]

    expect(first_nonce).to be_present
    expect(second_nonce).to be_present
    expect(first_nonce).not_to eq(second_nonce)
  end

  it 'does not use CSP-incompatible inline handlers on browser pages' do
    ['/api/v1/api-docs', '/api/v1/auth/login', '/api/v1/auth/account'].each do |path|
      get path

      expect(last_response.body).not_to match(/\son(?:click|load|error|submit|change)\s*=/i)
      expect(last_response.body).not_to include('javascript:')
    end
  end

  it 'adds HSTS only for requests that reached Rack over HTTPS' do
    get '/api/v1/health', {}, { 'rack.url_scheme' => 'https' }

    expect(last_response.headers['strict-transport-security']).to eq('max-age=31536000')
  end

  it 'does not trust a forwarded protocol header for HSTS' do
    get '/api/v1/health', {}, { 'HTTP_X_FORWARDED_PROTO' => 'https' }

    expect(last_response.headers).not_to have_key('strict-transport-security')
  end

  it 'keeps security headers on error responses' do
    get '/api/v1/does-not-exist'

    expect(last_response.status).to be_between(400, 599)
    expect(last_response.headers['content-security-policy']).to be_present
    expect(last_response.headers['x-content-type-options']).to eq('nosniff')
  end

  it 'serves the OAuth redirect script as a self-hosted external asset' do
    get '/oauth2-redirect.html'

    expect(last_response.status).to eq(200)
    expect(last_response.body).to include('src="oauth2-redirect.js"')
    expect(last_response.body).not_to include('onload=')
  end
end
