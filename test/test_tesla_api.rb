# frozen_string_literal: true

require 'bundler/setup'
require 'minitest/autorun'
require 'tmpdir'
require 'json'
require_relative '../lib/TeslaAPI'
require_relative '../lib/Config'

#----------------------------------------------------------------------------

class TeslaApiTestDouble < TeslaAPI
  attr_reader :api_requests, :auth_requests, :saved

  def initialize(config = {})
    @config = {
      local_interface:  '127.0.0.1',
      local_port:       8089,
      public_host:      'example.test',
      client_id:        'client-id',
      client_secret:    'client-secret',
      session_secret:   SecureRandom.hex(32),
      redirect_path:    '/auth/callback',
      redirect_uri:     'https://example.test/auth/callback',
      auth_host:        'fleet-auth.prd.vn.cloud.tesla.com',
      api_host:         'fleet-api.prd.na.vn.cloud.tesla.com',
      scopes:           'openid offline_access user_data',
      tesla_email:      nil,
      state_dir:        Dir.mktmpdir('tesla-api-test-'),
      state_dir_perms:  0o700,
      state_file_perms: 0o600
    }.merge(config)

    @tokens            = {}
    @token_mutex       = Mutex.new
    @api_requests      = []
    @auth_requests     = []
    @saved             = false
    @access_token_file = File.join(@config[:state_dir], 'tesla_access_token.json') if @config[:state_dir]
  end

  def api_request(verb, path, post_data = nil,
                  open_timeout: nil, read_timeout: nil, write_timeout: nil)
    @api_requests << {
      verb: verb,
      path: path,
      post_data: post_data,
      open_timeout: open_timeout,
      read_timeout: read_timeout,
      write_timeout: write_timeout
    }

    @api_response || [200, { response: { email: @config[:tesla_email] } }]
  end

  def auth_request(verb, path, post_data = nil,
                   open_timeout: nil, read_timeout: nil, write_timeout: nil)
    @auth_requests << {
      verb: verb,
      path: path,
      post_data: post_data,
      open_timeout: open_timeout,
      read_timeout: read_timeout,
      write_timeout: write_timeout
    }

    @auth_response || [200, {
      access_token:  'new-access',
      refresh_token: 'new-refresh',
      expires_in:    3600
    }]
  end

  def save_tokens
    @saved = true
  end

  def api_response=(response)
    @api_response = response
  end

  def auth_response=(response)
    @auth_response = response
  end

  def tokens=(tokens)
    @tokens = tokens
  end

  def tokens
    @tokens
  end
end

#----------------------------------------------------------------------------

class TeslaApiEndpointTestDouble < TeslaAPI
  attr_reader :tokens

  def initialize(config = {})
    @config = {
      local_interface:  '127.0.0.1',
      local_port:       8089,
      public_host:      'example.test',
      client_id:        'client-id',
      client_secret:    'client-secret',
      session_secret:   '0' * 64,
      redirect_path:    '/auth/callback',
      redirect_uri:     'https://example.test/auth/callback',
      auth_host:        'fleet-auth.prd.vn.cloud.tesla.com',
      api_host:         'fleet-api.prd.na.vn.cloud.tesla.com',
      scopes:           'openid offline_access user_data',
      tesla_email:      nil,
      state_dir:        "/tmp/state_dir_#{$$}",
      state_dir_perms:  0o700,
      state_file_perms: 0o600
    }.merge(config)

    @tokens = {}
    @token_mutex   = Mutex.new
    @command_mutex = Mutex.new
    @access_token_file =
      File.join(@config[:state_dir], 'tesla_access_token.json')
  end

  def set_tokens(tokens)
    @tokens = tokens
  end
end

#----------------------------------------------------------------------------

class TeslaApiOAuthTest < Minitest::Test
  def setup
    @api = TeslaApiTestDouble.new
  end

  def test_successful_authorization_code_exchange_updates_and_saves_tokens
    response_code = @api.exchange_authorization_code('auth-code')&.first

    assert_equal 200, response_code
    assert_equal 'new-access' , @api.tokens[:access_token]
    assert_equal 'new-refresh', @api.tokens[:refresh_token]
    assert @api.saved
    assert_equal :POST  , @api.auth_requests.first[:verb]
    assert_equal 'token', @api.auth_requests.first[:path]
  end

  def test_rejected_authorization_code_preserves_existing_tokens
    @api = TeslaApiTestDouble.new(
      tesla_email: 'alice@example.com'
    )

    old_tokens = {
      access_token:  'old-access',
      refresh_token: 'old-refresh',
      obtained_at:   1,
      expires_in:    3600
    }

    @api.tokens = old_tokens.dup

    @api.auth_response = [200, {
      access_token:  'new-access',
      refresh_token: 'new-refresh',
      expires_in:    3600
    }]

    @api.api_response = [
      200,
      { response: { email: 'bob@example.com' } }
    ]

    response_code, = @api.exchange_authorization_code('bob-code')

    assert_equal 403, response_code
    assert_equal old_tokens, @api.tokens
    refute @api.saved
  end

  def test_refresh_token_reuses_existing_refresh_token
    @api.tokens = {
      access_token: 'expired-access',
      refresh_token: 'refresh-me',
      obtained_at: 1,
      expires_in: 1
    }

    tokens_refreshed = @api.refresh_access_token

    assert tokens_refreshed
    assert_equal 'new-access' , @api.tokens[:access_token]
    assert_equal 'new-refresh', @api.tokens[:refresh_token]
    post_data = @api.auth_requests.first[:post_data]
    assert_equal 'refresh_token', post_data[:grant_type]
    assert_equal 'refresh-me'   , post_data[:refresh_token]
    assert @api.saved
  end

  def test_invalid_bearer_token_clears_tokens_and_token_file
    Dir.mktmpdir do |dir|
      @api = TeslaApiTestDouble.new(state_dir: dir)
      @api.tokens = { access_token: 'bad-token' }
      token_file = File.join(dir, 'tesla_access_token.json')
      File.write(token_file, JSON.generate(access_token: 'bad-token'))

      @api.send(:instance_variable_set, :@access_token_file, token_file)
      @api.update_tokens(403, error: 'invalid bearer token')

      assert_equal({}, @api.tokens)
      refute File.exist?(token_file)
    end
  end
end

#----------------------------------------------------------------------------

class TeslaApiEndpointTest < Minitest::Test
  def setup
    @api = TeslaApiTestDouble.new
  end

  def test_read_config
    @api.read_config('config', 'tesla_api.json')
    assert_match (/\A\w+\z/), @api.config[:client_id]
  end

  def test_validate_config
    @api.config.replace({})
    assert_raises(RuntimeError) { @api.validate_config }
  end

  def test_tesla_email_is_optional
    config = @api.instance_variable_get(:@config)

    config[:tesla_email] = nil

    assert_nil @api.validate_config(config)
  end

  def test_session_secret_is_required
    config = @api.instance_variable_get(:@config)
    config[:session_secret] = nil

    assert_raises(RuntimeError, /session_secret/) do
      @api.validate_config(config)
    end
  end

  def test_session_secret_is_rejected_when_invalid
    config = @api.instance_variable_get(:@config)

    config[:session_secret] = 'not-a-valid-secret'

    assert_raises(RuntimeError, /session_secret/) do
      @api.validate_config(config)
    end
  end

  def test_session_secret_must_be_at_least_64_hex_characters
    [
      '',
      'abc',
      'g' * 64,
      'a' * 63
    ].each do |secret|
      config = @api.instance_variable_get(:@config)

      config[:session_secret] = secret

      assert_raises(RuntimeError, /session_secret/) do
        @api.validate_config(config)
      end
    end
  end

  def test_tesla_email_is_rejected_when_invalid
    config = @api.instance_variable_get(:@config)

    config[:tesla_email] = 'not-an-email'

    assert_raises(RuntimeError, /tesla_email/) do
      @api.validate_config(config)
    end
  end

  def test_parse_perms
    assert_equal 123, @api.parse_perms(123)
    assert_equal 438, @api.parse_perms("0666")
    error = assert_raises { @api.parse_perms("xyx") }
    assert_match (/\AInvalid perms/), error.message
  end

  def test_have_access_token?
    @api.tokens.replace({})
    refute @api.have_access_token?
    @api.tokens.replace({access_token: '123'})
    assert @api.have_access_token?
  end

  def test_expand_api_path
    good_pattern = /https:\/\/#{Regexp.escape(@api.config[:api_host])}#{Regexp.escape(TeslaAPI::API_BASE_PATH)}\/vehicles/
    assert_match good_pattern, @api.expand_api_path("https://foo.com#{TeslaAPI::API_BASE_PATH}/vehicles")
    assert_match good_pattern, @api.expand_api_path("#{TeslaAPI::API_BASE_PATH}/vehicles")
    assert_match good_pattern, @api.expand_api_path("/vehicles")
    assert_match good_pattern, @api.expand_api_path("vehicles")
  end

  def test_expand_auth_path
    good_pattern = /https:\/\/#{Regexp.escape(@api.config[:auth_host])}#{Regexp.escape(TeslaAPI::AUTH_BASE_PATH)}\/tokens/
    @api.expand_auth_path("https://foo.com#{TeslaAPI::AUTH_BASE_PATH}/tokens")
    assert_match good_pattern, @api.expand_auth_path("https://foo.com#{TeslaAPI::AUTH_BASE_PATH}/tokens")
    assert_match good_pattern, @api.expand_auth_path("#{TeslaAPI::AUTH_BASE_PATH}/tokens")
    assert_match good_pattern, @api.expand_auth_path("/tokens")
    assert_match good_pattern, @api.expand_auth_path("tokens")
  end

  def test_id_or_vin_valid?
    assert @api.id_or_vin_valid?('ABC123')
    refute @api.id_or_vin_valid?(nil)
    refute @api.id_or_vin_valid?('abc')
    refute @api.id_or_vin_valid?('abc!')
    refute @api.id_or_vin_valid?('ABC#123')
    refute @api.id_or_vin_valid?('ABC/123')
    refute @api.id_or_vin_valid?('ABC?123')
    refute @api.id_or_vin_valid?('ABC 123')
    refute @api.id_or_vin_valid?('ABC%20123')
  end

  def test_normalize_endpoint
    raw_endpoint = 'vehicles'
    normalized_endpoint = @api.normalize_endpoint(raw_endpoint)
    assert_equal 'vehicles', normalized_endpoint
    raw_endpoint = '/vehicles'
    normalized_endpoint = @api.normalize_endpoint(raw_endpoint)
    assert_equal 'vehicles', normalized_endpoint
    raw_endpoint = "#{TeslaAPI::API_BASE_PATH}/vehicles"
    normalized_endpoint = @api.normalize_endpoint(raw_endpoint)
    assert_equal "vehicles", normalized_endpoint
  end

  def test_normalize_endpoint_abbreviations
    raw_endpoint = 'vehicle_state'
    normalized_endpoint = @api.normalize_endpoint(raw_endpoint)
    assert_equal "vehicle_data?endpoints=vehicle_state", normalized_endpoint
  end

  def test_normalize_endpoint_multiple_endpoints
    raw_endpoint = 'vehicle_data?endpoints=vehicle_state;location_data'
    normalized_endpoint = @api.normalize_endpoint(raw_endpoint)
    assert_equal "vehicle_data?endpoints=vehicle_state;location_data", normalized_endpoint
  end

  def test_match_endpoint
    id_or_vin = '12345'
    uri = URI.parse('vehicles')
    assert_equal [:GET, 'vehicles'], @api.match_endpoint(uri, :GET, id_or_vin)
    uri = URI.parse('vehicle_data')
    assert_equal [:GET, "vehicles/#{id_or_vin}/vehicle_data"], @api.match_endpoint(uri, :GET, id_or_vin)
    uri = URI.parse("vehicles/#{id_or_vin}/vehicle_data")
    assert_equal [:GET, "vehicles/#{id_or_vin}/vehicle_data"], @api.match_endpoint(uri, :GET, id_or_vin)
    uri = URI.parse('wake_up')
    assert_equal [:POST, "vehicles/#{id_or_vin}/wake_up"], @api.match_endpoint(uri, :GET, id_or_vin)
    uri = URI.parse('dx/warranty/details')
    assert_equal [:GET, 'dx/warranty/details'], @api.match_endpoint(uri, :GET, id_or_vin)
    uri = URI.parse('dx/vehicles/upgrades/eligibility')
    assert_equal [:GET, "dx/vehicles/upgrades/eligibility?vin=#{id_or_vin}"], @api.match_endpoint(uri, :GET, id_or_vin)
    uri = URI.parse('dx/vehicles/upgrades/eligibility?vin={vin}')
    assert_equal [:GET, "dx/vehicles/upgrades/eligibility?vin=#{id_or_vin}"], @api.match_endpoint(uri, :GET, id_or_vin)
    uri = URI.parse('dx/vehicles/pricing')
    assert_equal [:POST, 'dx/vehicles/pricing'], @api.match_endpoint(uri, :POST, id_or_vin)
    uri = URI.parse('foo')
    error = assert_raises { @api.match_endpoint(uri, :GET, id_or_vin) }
    assert_match (/\AInvalid endpoint/), error.message
  end

  def test_assemble_endpoint_non_vehicle_data
    id_or_vin = nil
    raw_endpoint = 'vehicles'
    uri = URI.parse(@api.normalize_endpoint(raw_endpoint))
    match = 'vehicles'
    url = @api.assemble_endpoint(uri, match, id_or_vin)
    assert_equal "#{TeslaAPI::API_BASE_PATH}/vehicles", url
  end

  def test_assemble_endpoint_vehicle_data
    id_or_vin = '12345'
    raw_endpoint = 'vehicle_data?endpoints=vehicle_state;location_data'
    uri = URI.parse(@api.normalize_endpoint(raw_endpoint))
    match = 'vehicles/{vin}/vehicle_data'
    url = @api.assemble_endpoint(uri, match, id_or_vin)
    assert_equal "#{TeslaAPI::API_BASE_PATH}/vehicles/#{id_or_vin}/vehicle_data?endpoints=vehicle_state%3Blocation_data", url
  end

  def test_assemble_endpoint_vin_in_params
    id_or_vin = '12345'
    raw_endpoint = 'dx/warranty/options?vin={vin}'
    uri = URI.parse(@api.normalize_endpoint(raw_endpoint))
    match = 'dx/warranty/options?vin={vin}'
    url = @api.assemble_endpoint(uri, match, id_or_vin)
    assert_equal "#{TeslaAPI::API_BASE_PATH}/dx/warranty/options?vin=12345", url
  end

  def test_assemble_endpoint_malformed_vin_in_params
    id_or_vin = '12345'

    raw_endpoint = 'dx/warranty/options?vin=1 2'
    uri = URI.parse(@api.normalize_endpoint(raw_endpoint))
    match = 'dx/warranty/options?vin={vin}'
    url = @api.assemble_endpoint(uri, match, id_or_vin)
    assert_equal "#{TeslaAPI::API_BASE_PATH}/dx/warranty/options?vin=1+2", url

    raw_endpoint = 'dx/warranty/options?vin=1/2'
    uri = URI.parse(@api.normalize_endpoint(raw_endpoint))
    match = 'dx/warranty/options?vin={vin}'
    url = @api.assemble_endpoint(uri, match, id_or_vin)
    assert_equal "#{TeslaAPI::API_BASE_PATH}/dx/warranty/options?vin=1%2F2", url
  end

  def test_assemble_endpoint_vin_no_params
    id_or_vin = '12345'
    raw_endpoint = 'dx/warranty/details'
    uri = URI.parse(@api.normalize_endpoint(raw_endpoint))
    match = 'dx/warranty/details'
    url = @api.assemble_endpoint(uri, match, id_or_vin)
    assert_equal "#{TeslaAPI::API_BASE_PATH}/dx/warranty/details", url
  end

  def test_vehicle_data_query_is_not_encoded_as_one_query_component
    verb, endpoint = @api.find_endpoint(
      'vehicle_data?endpoints=charge_state;climate_state',
      '12345',
      :GET
    )

    assert_equal :GET, verb
    uri = URI(endpoint)
    assert_equal "#{TeslaAPI::API_BASE_PATH}/vehicles/12345/vehicle_data", uri.path
    params = URI.decode_www_form(uri.query).to_h
    assert_equal 'charge_state;climate_state', params['endpoints']
  end

  def test_vehicle_data_shorthand_expands_to_configured_vehicle
    verb, endpoint = @api.find_endpoint('location_data', '12345', :GET)

    assert_equal :GET, verb
    assert_equal "https://#{@api.config[:api_host]}#{TeslaAPI::API_BASE_PATH}/vehicles/12345/vehicle_data?endpoints=location_data", @api.expand_api_path(endpoint)
  end

  def test_vehicle_endpoint_can_be_requested_without_api_prefix
    verb, endpoint = @api.find_endpoint('vehicles/12345', '12345', :GET)

    assert_equal :GET, verb
    assert_equal "https://#{@api.config[:api_host]}#{TeslaAPI::API_BASE_PATH}/vehicles/12345", @api.expand_api_path(endpoint)
  end

  def test_vehicle_id_is_inserted_for_vin_query_parameter
    verb, endpoint = @api.find_endpoint('dx/vehicles/options', '12345', :GET)

    assert_equal :GET, verb
    uri = URI(endpoint)
    assert_equal "#{TeslaAPI::API_BASE_PATH}/dx/vehicles/options", uri.path
    assert_equal 'vin=12345', uri.query
  end

  def test_vehicle_endpoint_without_trailing_path_is_vehicle_endpoint
    verb, endpoint =
      @api.find_endpoint('vehicles/12345', '12345', :GET)

    assert_equal :GET, verb
    assert_equal "#{TeslaAPI::API_BASE_PATH}/vehicles/12345",
                 URI(endpoint).path
  end

  def test_process_endpoints_supports_account_level_endpoint_without_vehicle_id
    @api.api_response = [200, { response: [{ id: 12345, vin: 'VIN123' }] }]

    json = @api.process_endpoints('vehicles', nil)
    result = JSON.parse(json)

    assert_equal [{ 'id' => 12345, 'vin' => 'VIN123' }], result['response']
    assert_equal 1, @api.api_requests.length
  end

  def test_invalid_endpoint_is_rejected
    assert_raises(RuntimeError) do
      @api.find_endpoint('not-a-real-tesla-endpoint', '12345', :GET)
    end
  end

  def test_408_does_not_automatically_mark_vehicle_as_sleeping
    endpoints = [
      {
        verb:     :GET,
        endpoint: "#{TeslaAPI::API_BASE_PATH}/vehicles/1234567890123456/vehicle_data"
      },
      {
        verb:     :GET,
        endpoint: "#{TeslaAPI::API_BASE_PATH}/vehicles/1234567890123456/charge_state"
      }
    ]

    calls = []

    @api.stub(:find_endpoints, endpoints) do
      @api.stub(
        :api_request,
        lambda { |verb, endpoint, post_data = nil|
          calls << [verb, endpoint]

          if endpoint.end_with?('/vehicle_data')
            [408, { error: 'request timeout' }]
          else
            [200, { response: { charging_state: 'Disconnected' } }]
          end
        }
      ) do
        @api.process_endpoints(
          ['vehicle_data', 'charge_state'],
          ['1234567890123456']
        )
      end
    end

    # This assertion documents the current intended behavior:
    # a generic HTTP 408 should not automatically suppress
    # subsequent vehicle requests.
    assert_equal 2, calls.length
  end

  # ------------------------------------------------------------
  # OAuth login URL
  # ------------------------------------------------------------

  def test_generate_login_url_contains_expected_oauth_parameters
    state = 'test-state-123'

    url = @api.generate_login_url(state)

    uri = URI.parse(url)
    params = Rack::Utils.parse_nested_query(uri.query)

    assert_equal @api.config[:client_id],
                 params['client_id']

    assert_equal @api.config[:redirect_uri],
                 params['redirect_uri']

    assert_equal @api.config[:scopes],
                 params['scope']

    assert_equal state,
                 params['state']

    assert_equal 'code',
                 params['response_type']
  end

  def test_generate_login_url_uses_tesla_auth_host
    url = @api.generate_login_url('state')

    uri = URI.parse(url)

    assert_equal @api.config[:auth_host],
                 uri.host
  end

  def test_generate_login_url_uses_https
    url = @api.generate_login_url('state')

    uri = URI.parse(url)

    assert_equal 'https', uri.scheme
  end

  def test_generate_login_url_preserves_state_exactly
    state = SecureRandom.urlsafe_base64(32)

    url = @api.generate_login_url(state)

    params =
      Rack::Utils.parse_nested_query(
        URI.parse(url).query
      )

    assert_equal state, params['state']
  end

  # ------------------------------------------------------------
  # Configuration validation
  # ------------------------------------------------------------

  def test_redirect_path_must_begin_with_slash
    config = @api.instance_variable_get(:@config)

    config[:redirect_path] = 'auth/callback'

    assert_raises(RuntimeError) do
      @api.validate_config(config)
    end
  end

  def test_redirect_path_rejects_query_string
    config = @api.instance_variable_get(:@config)

    config[:redirect_path] = '/auth/callback?evil=true'

    assert_raises(RuntimeError) do
      @api.validate_config(config)
    end
  end

  def test_redirect_path_rejects_fragment
    config = @api.instance_variable_get(:@config)

    config[:redirect_path] = '/auth/callback#evil'

    assert_raises(RuntimeError) do
      @api.validate_config(config)
    end
  end

  def test_redirect_path_accepts_normal_path
    config = @api.instance_variable_get(:@config)

    config[:redirect_path] = '/auth/callback'

    assert_nil @api.validate_config(config)
  end

  def test_state_directory_permissions_are_validated
    config = @api.instance_variable_get(:@config)

    config[:state_dir_perms] = '0777'

    assert_nil @api.validate_config(config)
  end

  def test_state_file_permissions_are_validated
    config = @api.instance_variable_get(:@config)

    config[:state_file_perms] = '0600'

    assert_nil @api.validate_config(config)
  end

  def test_state_directory_permissions_cannot_exceed_octal_range
    config = @api.instance_variable_get(:@config)

    config[:state_dir_perms] = '10000'

    assert_raises(RuntimeError) do
      @api.validate_config(config)
    end
  end

  def test_state_file_permissions_cannot_exceed_octal_range
    config = @api.instance_variable_get(:@config)

    config[:state_file_perms] = '10000'

    assert_raises(RuntimeError) do
      @api.validate_config(config)
    end
  end

end

#----------------------------------------------------------------------------

class TeslaApiRequestTest < Minitest::Test
  def setup
    @api = TeslaApiEndpointTestDouble.new
  end

  def test_api_request_uses_valid_access_token_without_refresh
    @api.set_tokens(
      access_token: 'valid-access',
      refresh_token: 'refresh-token',
      obtained_at: Time.now.to_i,
      expires_in: 3600
    )

    captured = nil

    @api.stub(
      :request_data,
      lambda { |access_token, verb, url, post_data = nil,
               open_timeout: nil, read_timeout: nil, write_timeout: nil|
        captured = {
          access_token: access_token,
          verb: verb,
          url: url,
          post_data: post_data,
          open_timeout: open_timeout,
          read_timeout: read_timeout,
          write_timeout: write_timeout
        }

        [200, { response: { ok: true } }]
      }
    ) do
      result = @api.api_request(:GET, 'vehicles')
      assert_equal [200, { response: { ok: true } }], result
    end

    assert_equal 'valid-access', captured[:access_token]
    assert_equal :GET, captured[:verb]
    assert_equal(
      'https://fleet-api.prd.na.vn.cloud.tesla.com/api/1/vehicles',
      captured[:url]
    )
  end

  def test_api_request_refreshes_expired_access_token_before_request
    @api.set_tokens(
      access_token: 'expired-access',
      refresh_token: 'refresh-token',
      obtained_at: 1,
      expires_in: 1
    )

    auth_calls = []

    @api.stub(
      :auth_request,
      lambda { |verb, path, post_data = nil,
               open_timeout: nil, read_timeout: nil, write_timeout: nil|
        auth_calls << {
          verb: verb,
          path: path,
          post_data: post_data,
          open_timeout: open_timeout,
          read_timeout: read_timeout,
          write_timeout: write_timeout
        }

        [
          200,
          {
            access_token: 'refreshed-access',
            refresh_token: 'refreshed-refresh',
            expires_in: 3600
          }
        ]
      }
    ) do
      @api.stub(:save_tokens, true) do
        @api.stub(
          :request_data,
          lambda { |access_token, verb, url, post_data = nil,
                   open_timeout: nil, read_timeout: nil, write_timeout: nil|
            [200, { response: { ok: true } }]
          }
        ) do
          result = @api.api_request(:GET, 'vehicles')

          assert_equal [200, { response: { ok: true } }], result
        end
      end
    end

    assert_equal 1, auth_calls.length

    assert_equal :POST, auth_calls.first[:verb]
    assert_equal 'token', auth_calls.first[:path]

    assert_equal 'refresh_token',
                 auth_calls.first[:post_data][:grant_type]

    assert_equal 'refresh-token',
                 auth_calls.first[:post_data][:refresh_token]

    assert_equal 'refreshed-access',
                 @api.tokens[:access_token]
  end

  def test_api_request_returns_500_when_expired_token_cannot_be_refreshed
    @api.set_tokens(
      access_token: 'expired-access',
      refresh_token: 'refresh-token',
      obtained_at: 1,
      expires_in: 1
    )

    @api.stub(
      :auth_request,
      lambda { |*args, **kwargs|
        [400, { error: 'invalid_grant' }]
      }
    ) do
      result = @api.api_request(:GET, 'vehicles')

      assert_equal(
        [500, { error: 'Unable to refresh access token' }],
        result
      )
    end
  end

  def test_api_request_returns_401_when_not_logged_in
    @api.set_tokens({})

    result = @api.api_request(:GET, 'vehicles')

    assert_equal [401, { error: 'Not logged in' }], result
  end

  def test_api_request_passes_timeouts_to_request_data
    @api.set_tokens(
      access_token: 'valid-access',
      refresh_token: 'refresh-token',
      obtained_at: Time.now.to_i,
      expires_in: 3600
    )

    captured = nil

    @api.stub(
      :request_data,
      lambda { |access_token, verb, url, post_data = nil,
               open_timeout: nil, read_timeout: nil, write_timeout: nil|
        captured = {
          access_token: access_token,
          verb: verb,
          url: url,
          post_data: post_data,
          open_timeout: open_timeout,
          read_timeout: read_timeout,
          write_timeout: write_timeout
        }

        [200, { response: { ok: true } }]
      }
    ) do
      result = @api.api_request(
        :GET,
        'vehicles',
        nil,
        open_timeout: 11,
        read_timeout: 22,
        write_timeout: 33
      )

      assert_equal [200, { response: { ok: true } }], result
    end

    refute_nil captured

    assert_equal 'valid-access', captured[:access_token]
    assert_equal :GET, captured[:verb]
    assert_equal 11, captured[:open_timeout]
    assert_equal 22, captured[:read_timeout]
    assert_equal 33, captured[:write_timeout]
  end

  def test_api_request_clears_tokens_after_invalid_bearer_response
    Dir.mktmpdir do |dir|
      @api = TeslaApiEndpointTestDouble.new(state_dir: dir)

      @api.set_tokens(
        access_token: 'bad-access',
        refresh_token: 'refresh-token',
        obtained_at: Time.now.to_i,
        expires_in: 3600
      )

      token_file = File.join(dir, 'tesla_access_token.json')

      File.write(
        token_file,
        JSON.generate(
          access_token: 'bad-access',
          refresh_token: 'refresh-token'
        )
      )

      @api.instance_variable_set(:@access_token_file, token_file)

      @api.stub(
        :request_data,
        lambda { |*args, **kwargs|
          [401, { error: 'invalid bearer token' }]
        }
      ) do
        result = @api.api_request(:GET, 'vehicles')

        assert_equal(
          [401, { error: 'invalid bearer token' }],
          result
        )
      end

      assert_equal({}, @api.tokens)
      refute File.exist?(token_file)
    end
  end

  def test_api_request_accepts_signed_command_path
    @api.set_tokens(
      access_token: 'valid-access',
      refresh_token: 'refresh-token',
      obtained_at: Time.now.to_i,
      expires_in: 3600
    )

    captured = nil

    @api.stub(
      :request_data,
      lambda { |access_token, verb, url, post_data = nil,
               open_timeout: nil, read_timeout: nil, write_timeout: nil|
        captured = {
          access_token: access_token,
          verb: verb,
          url: url,
          post_data: post_data
        }

        [200, { response: 'ok' }]
      }
    ) do
      result = @api.api_request(
        :POST,
        'vehicles/5YJTESTVIN1234567/commands'
      )

      assert_equal [200, { response: 'ok' }], result
    end

    assert_equal 'valid-access', captured[:access_token]
    assert_equal :POST, captured[:verb]

    assert_equal(
      'https://fleet-api.prd.na.vn.cloud.tesla.com/api/1/vehicles/5YJTESTVIN1234567/commands',
      captured[:url]
    )
  end

  def test_partner_account_request_uses_partner_authentication_token
    @api.set_tokens(
      access_token: 'normal-access',
      refresh_token: 'refresh-token',
      obtained_at: Time.now.to_i,
      expires_in: 3600
    )

    @api.stub(
      :get_partner_authentication_token,
      'partner-access'
    ) do
      captured = nil

      @api.stub(
        :request_data,
        lambda { |access_token, verb, url, post_data = nil,
                 open_timeout: nil, read_timeout: nil, write_timeout: nil|
          captured = {
            access_token: access_token,
            verb: verb,
            url: url,
            post_data: post_data
          }

          [200, { response: { ok: true } }]
        }
      ) do
        result = @api.api_request(
          :GET,
          'partner_accounts/example-account'
        )

        assert_equal [200, { response: { ok: true } }], result
      end

      refute_nil captured
      assert_equal 'partner-access', captured[:access_token]
    end
  end

  def test_request_data_handles_write_timeout
    Https.stub(
      :get,
      ->(
        url,
        headers,
        open_timeout: nil,
        read_timeout: nil,
        write_timeout: nil
      ) {
        raise Net::WriteTimeout,
              "timed out writing request"
      }
    ) do
      response_code, data =
        @api.request_data(
          "ACCESS-TOKEN",
          :GET,
          "https://example.test/test",
          nil,
          open_timeout: 10,
          read_timeout: 20,
          write_timeout: 30
        )

      assert_equal(
        500,
        response_code
      )

      assert_equal(
        "connection_error (Net::WriteTimeout)",
        data[:error]
      )
    end
  end

  def test_http_408_is_reported_as_vehicle_asleep
    @api.tokens[:access_token] = "valid-access"

    error =
      Tesla::FleetAPIError.new(
        status: 408,
        body: {}
      )

    Tesla::VehicleCommand.stub(
      :command,
      ->(*) { raise error }
    ) do
      result =
        assert_raises(RuntimeError) do
          @api.issue_command(
            :vehicle_command,
            "lock",
            "5YJTESTVIN1234567"
          )
        end

      assert_equal(
        "Vehicle is asleep",
        result.message
      )
    end
  end

  def test_http_408_uses_status_not_error_message
    @api.tokens[:access_token] = "valid-access"

    error =
      Tesla::FleetAPIError.new(
        status: 408,
        body: {},
        message: "completely different message"
      )

    Tesla::VehicleCommand.stub(
      :command,
      ->(*) { raise error }
    ) do
      result =
        assert_raises(RuntimeError) do
          @api.issue_command(
            :vehicle_command,
            "lock",
            "5YJTESTVIN1234567"
          )
        end

      assert_equal(
        "Vehicle is asleep",
        result.message
      )
    end
  end

  def test_tls_verification_failure_is_not_converted_to_http_500
    error =
      OpenSSL::SSL::SSLError.new(
        "certificate verify failed"
      )

    assert_raises(Tesla::TLSConnectionError) do
      Https.stub(
        :get,
        ->(*) { raise error }
      ) do
        @api.request_data(
          "ACCESS-TOKEN",
          :GET,
          "https://example.test/test"
        )
      end
    end
  end

  def test_tls_verification_failure_is_not_retryable
    error =
      Tesla::TLSConnectionError.new(
        "TLS connection failed"
      )

    assert_equal(
      :tls,
      Tesla::ErrorClassifier.classify(error)
    )

    refute(
      Tesla::ErrorClassifier.retryable?(error)
    )
  end

end

#----------------------------------------------------------------------------
