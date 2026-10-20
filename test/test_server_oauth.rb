# frozen_string_literal: true

require_relative 'test_helper'
require 'rack/test'

require_relative '../tesla_api_server'

class OAuthCallbackTest < Minitest::Test
  include Rack::Test::Methods

  TEST_STATE = 'test-oauth-state-1234567890'

  def app
    Sinatra::Application
  end

  def api
    app.settings.tesla_api
  end

  # ------------------------------------------------------------
  # /auth/start
  # ------------------------------------------------------------

  def test_auth_start_generates_state_and_redirects
    SecureRandom.stub(:urlsafe_base64, TEST_STATE) do
      api.stub(
        :generate_login_url,
        "https://auth.tesla.com/authorize?state=#{TEST_STATE}"
      ) do
        get '/auth/start'
      end
    end

    assert_equal 302, last_response.status

    location = last_response['Location']

    assert_includes location, TEST_STATE
  end

  # ------------------------------------------------------------
  # /auth/callback
  # ------------------------------------------------------------

  def test_callback_rejects_missing_state
    get '/auth/callback', code: 'oauth-code'

    assert_equal 400, last_response.status

    assert_includes(
      last_response.body,
      'Invalid state parameter'
    )
  end

  def test_callback_rejects_wrong_state
    start_oauth_flow

    exchange_called = false

    api.stub(
      :exchange_authorization_code,
      lambda { |_code|
        exchange_called = true
        [200, {}]
      }
    ) do
      get '/auth/callback',
          state: 'wrong-state',
          code: 'oauth-code'
    end

    assert_equal 400, last_response.status

    assert_includes(
      last_response.body,
      'Invalid state parameter'
    )

    refute(
      exchange_called,
      'authorization code must not be exchanged when state is invalid'
    )
  end

  def test_callback_accepts_correct_state
    start_oauth_flow

    exchange_called_with = nil

    api.stub(
      :exchange_authorization_code,
      lambda { |code|
        exchange_called_with = code
        [200, {}]
      }
    ) do
      get '/auth/callback',
          state: TEST_STATE,
          code: 'oauth-code'
    end

    assert_equal 302, last_response.status
    assert_equal 'oauth-code', exchange_called_with
  end

  def test_callback_state_is_single_use
    start_oauth_flow

    exchange_count = 0

    api.stub(
      :exchange_authorization_code,
      lambda { |_code|
        exchange_count += 1
        [200, {}]
      }
    ) do
      # First request must succeed.
      get '/auth/callback',
          state: TEST_STATE,
          code: 'oauth-code'

      assert_equal 302, last_response.status

      # Reusing the same state must fail.
      get '/auth/callback',
          state: TEST_STATE,
          code: 'oauth-code'
    end

    assert_equal 400, last_response.status

    assert_includes(
      last_response.body,
      'Invalid state parameter'
    )

    assert_equal 1, exchange_count
  end

  def test_invalid_state_prevents_authorization_code_exchange
    start_oauth_flow

    api.stub(
      :exchange_authorization_code,
      ->(*) { flunk 'authorization code exchange must not be called' }
    ) do
      get '/auth/callback',
          state: 'attacker-controlled-state',
          code: 'oauth-code'
    end

    assert_equal 400, last_response.status
  end

  def test_callback_rejects_missing_code
    start_oauth_flow

    api.stub(
      :exchange_authorization_code,
      ->(*) { flunk 'authorization code exchange must not be called' }
    ) do
      get '/auth/callback',
          state: TEST_STATE
    end

    assert_equal 400, last_response.status

    assert_includes(
      last_response.body,
      'Missing authorization code'
    )
  end

  def test_callback_rejects_tesla_authorization_error
    start_oauth_flow

    api.stub(
      :exchange_authorization_code,
      ->(*) { flunk 'authorization code exchange must not be called' }
    ) do
      get '/auth/callback',
          state: TEST_STATE,
          error: 'access_denied'
    end

    assert_equal 400, last_response.status

    assert_includes(
      last_response.body,
      'Unable to complete Tesla authentication'
    )
  end

  def test_callback_handles_wrong_tesla_user
    start_oauth_flow

    api.stub(
      :exchange_authorization_code,
      [403, { error: 'wrong user' }]
    ) do
      get '/auth/callback',
          state: TEST_STATE,
          code: 'oauth-code'
    end

    assert_equal 403, last_response.status

    assert_includes(
      last_response.body,
      'Incorrect user for application'
    )
  end

  def test_callback_handles_token_exchange_failure
    start_oauth_flow

    api.stub(
      :exchange_authorization_code,
      [500, { error: 'server error' }]
    ) do
      get '/auth/callback',
          state: TEST_STATE,
          code: 'oauth-code'
    end

    assert_equal 400, last_response.status

    assert_includes(
      last_response.body,
      'Token exchange failed'
    )
  end

  def test_callback_does_not_expose_token_exchange_exception
    start_oauth_flow

    api.stub(
      :exchange_authorization_code,
      ->(*) { raise StandardError, 'database password is SECRET123' }
    ) do
      get '/auth/callback',
          state: TEST_STATE,
          code: 'oauth-code'
    end

    assert_equal 500, last_response.status

    refute_includes(
      last_response.body,
      'database password is SECRET123'
    )

    assert_includes(
      last_response.body,
      'Unable to complete Tesla authentication'
    )
  end

  # ------------------------------------------------------------
  # Helpers
  # ------------------------------------------------------------

  def start_oauth_flow
    SecureRandom.stub(:urlsafe_base64, TEST_STATE) do
      api.stub(
        :generate_login_url,
        "https://auth.tesla.com/authorize?state=#{TEST_STATE}"
      ) do
        get '/auth/start'
      end
    end

    assert_equal 302, last_response.status
  end

  # ------------------------------------------------------------
  # Constant-time state comparison
  # ------------------------------------------------------------

  def test_callback_uses_secure_compare_for_state
    start_oauth_flow

    secure_compare_called = false
    compared_state = nil
    expected_state = nil

    Rack::Utils.stub(
      :secure_compare,
      lambda { |provided, expected|
        secure_compare_called = true
        compared_state = provided
        expected_state = expected

        # Return true so the request proceeds past state validation.
        true
      }
    ) do
      api.stub(
        :exchange_authorization_code,
        [200, {}]
      ) do
        get '/auth/callback',
            state: TEST_STATE,
            code: 'oauth-code'
      end
    end

    assert secure_compare_called

    assert_equal TEST_STATE, compared_state
    assert_equal TEST_STATE, expected_state

    assert_equal 302, last_response.status
  end

end
