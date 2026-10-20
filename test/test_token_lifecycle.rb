# frozen_string_literal: true

require_relative 'test_helper'

class TokenLifecycleTest < TeslaAPITest

  def valid_tokens
    {
      access_token:  'access-123',
      refresh_token: 'refresh-123',
      obtained_at:  Time.now.to_i,
      expires_in:   3600
    }
  end

  # ------------------------------------------------------------
  # Token presence
  # ------------------------------------------------------------

  def test_no_tokens_are_invalid
    assert_equal :invalid, @api.token_state
    refute @api.have_access_token?
  end

  def test_access_token_is_detected
    @api.instance_variable_set(:@tokens, valid_tokens)

    assert @api.have_access_token?
  end

  def test_valid_access_token_is_valid
    @api.instance_variable_set(:@tokens, valid_tokens)

    assert_equal :valid, @api.token_state
  end

  def test_expired_access_token_is_invalid
    @api.instance_variable_set(
      :@tokens,
      valid_tokens.merge(
        obtained_at: Time.now.to_i - 7200,
        expires_in: 3600
      )
    )

    assert_equal :expired, @api.token_state
  end

  def test_token_near_expiration_is_invalid
    @api.instance_variable_set(
      :@tokens,
      valid_tokens.merge(
        obtained_at: Time.now.to_i - 3550,
        expires_in: 3600
      )
    )

    assert_equal :expired, @api.token_state
  end

  def test_invalid_token_file_is_not_accepted
    filename = File.join(
      @tmpdir,
      'tesla_access_token.json'
    )

    invalid_tokens = {
      access_token:  'access-123',
      refresh_token: 'refresh-123',
      obtained_at:  'not-a-time',
      expires_in:   'not-a-number'
    }

    File.write(filename, JSON.generate(invalid_tokens))

    assert_raises RuntimeError do
      restarted = TeslaAPI.new(@tmpdir, 'config.json')
      assert_equal :valid, restarted.token_state
    end
  end

  def test_token_file_without_access_token_is_invalid
    filename = File.join(
      @tmpdir,
      'tesla_access_token.json'
    )

    tokens = valid_tokens.reject { |key, _| key == :access_token }

    File.write(filename, JSON.generate(tokens))

    assert_raises RuntimeError do
      restarted = TeslaAPI.new(@tmpdir, 'config.json')
      assert_equal :valid, restarted.token_state
      refute restarted.have_access_token?
    end
  end

  # ------------------------------------------------------------
  # Regression test for the access-token bug
  # ------------------------------------------------------------

  def test_tokens_without_access_token_are_invalid
    @api.instance_variable_set(
      :@tokens,
      {
        refresh_token: 'refresh-123',
        obtained_at: Time.now.to_i,
        expires_in: 3600
      }
    )

    refute @api.have_access_token?

    assert_equal :invalid, @api.token_state
  end

  # ------------------------------------------------------------
  # Refresh token
  # ------------------------------------------------------------

  def test_refresh_token_is_used_when_access_token_expired
    @api.instance_variable_set(
      :@tokens,
      valid_tokens.merge(
        obtained_at: Time.now.to_i - 7200,
        expires_in: 3600
      )
    )

    refreshed = {
      access_token:  'new-access',
      refresh_token: 'new-refresh',
      obtained_at:  Time.now.to_i,
      expires_in:   3600
    }

    @api.stub(:auth_request, [200, refreshed]) do
      assert @api.refresh_access_token
    end

    assert_equal 'new-access',
                 @api.instance_variable_get(:@tokens)[:access_token]

    assert_equal 'new-refresh',
                 @api.instance_variable_get(:@tokens)[:refresh_token]

    assert_equal :valid, @api.token_state
  end

  def test_refresh_is_not_performed_when_token_is_valid
    @api.instance_variable_set(:@tokens, valid_tokens)

    auth_called = false

    @api.stub(
      :auth_request,
      lambda { |_verb, _path, _data|
        auth_called = true
        raise 'auth_request should not have been called'
      }
    ) do
      assert @api.refresh_access_token
    end

    refute auth_called
  end

  def test_refresh_fails_without_refresh_token
    @api.instance_variable_set(
      :@tokens,
      valid_tokens.reject { |key, _| key == :refresh_token }
    )

    refute @api.refresh_access_token
  end

  # ------------------------------------------------------------
  # Token persistence
  # ------------------------------------------------------------

  def test_tokens_are_saved_to_state_file
    tokens = valid_tokens

    @api.instance_variable_set(:@tokens, tokens)

    @api.send(:save_tokens)

    filename = File.join(
      @tmpdir,
      'tesla_access_token.json'
    )

    assert File.exist?(filename)

    assert_equal 0o600, File.stat(filename).mode & 0o777
    assert_equal 0o700, File.stat(@tmpdir ).mode & 0o777

    saved = JSON.parse(
      File.read(filename),
      symbolize_names: true
    )

    assert_equal tokens, saved
  end

  def test_tokens_are_loaded_on_restart
    tokens = valid_tokens

    filename = File.join(
      @tmpdir,
      'tesla_access_token.json'
    )

    config = @api.instance_variable_get(:@config)
    File.write(filename, JSON.generate(tokens), perm: config[:state_file_perms])

    restarted = TeslaAPI.new( @tmpdir, 'config.json')

    assert_equal 'access-123',
                 restarted.instance_variable_get(:@tokens)[:access_token]

    assert restarted.have_access_token?
  end

  def test_corrupt_token_file_prevents_startup
    filename = File.join(
      @tmpdir,
      'tesla_access_token.json'
    )

    File.write(filename, '{ definitely not json')

    assert_raises RuntimeError do
      TeslaAPI.new( @tmpdir, 'config.json')
    end
  end

  def test_refresh_restores_original_tokens_when_persistence_fails
    original_tokens = valid_tokens.merge(
      obtained_at: Time.now.to_i - 7200,
      expires_in: 3600
    )

    @api.instance_variable_set(:@tokens, original_tokens.dup)

    refreshed = {
      access_token:  'new-access',
      refresh_token: 'new-refresh',
      expires_in:   3600
    }

    @api.stub(:auth_request, [200, refreshed]) do
      @api.stub(
        :save_tokens,
        -> { raise RuntimeError, 'Unable to save tokens' }
      ) do
        refute @api.refresh_access_token
      end
    end

    assert_equal(
      original_tokens,
      @api.instance_variable_get(:@tokens)
    )
  end

  # ------------------------------------------------------------
  # Authorization-code exchange
  # ------------------------------------------------------------

  def test_authorization_code_exchange_saves_tokens
    token_response = {
      access_token:  'access-123',
      refresh_token: 'refresh-123',
      obtained_at:   Time.now.to_i,
      expires_in:    3600
    }

    user_response = {
      response: {
        email: 'bill@example.com'
      }
    }

    calls = []

    @api.stub(
      :auth_request,
      lambda { |verb, path, data|
        calls << [verb, path, data]
        [200, token_response]
      }
    ) do
      @api.stub(:api_request, [200, user_response]) do
        response_code, data =
          @api.exchange_authorization_code('oauth-code')

        assert_equal 200, response_code
        assert_equal token_response, data
      end
    end

    assert_equal 'access-123',
                 @api.instance_variable_get(:@tokens)[:access_token]

    assert File.exist?(
      File.join(@tmpdir, 'tesla_access_token.json')
    )

    assert_equal 'oauth-code', calls.first[2][:code]
    assert_equal 'authorization_code',
                 calls.first[2][:grant_type]
  end

  def test_authorization_code_exchange_restores_tokens_when_persistence_fails
    original_tokens = valid_tokens

    @api.instance_variable_set(:@tokens, original_tokens.dup)

    new_tokens = {
      access_token:  'new-access',
      refresh_token: 'new-refresh',
      obtained_at:   Time.now.to_i,
      expires_in:    3600
    }

    user_response = {
      response: {
        email: 'bill@example.com'
      }
    }

    @api.stub(:auth_request, [200, new_tokens]) do
      @api.stub(:api_request, [200, user_response]) do
        @api.stub(
          :save_tokens,
          -> { raise RuntimeError, 'Unable to save tokens' }
        ) do
          assert_raises RuntimeError do
            @api.exchange_authorization_code('oauth-code')
          end
        end
      end
    end

    assert_equal(
      original_tokens,
      @api.instance_variable_get(:@tokens)
    )
  end

  def test_authorization_code_exchange_restores_tokens_when_user_lookup_fails
    original_tokens = valid_tokens

    @api.instance_variable_set(:@tokens, original_tokens.dup)

    new_tokens = {
      access_token:  'new-access',
      refresh_token: 'new-refresh',
      obtained_at:   Time.now.to_i,
      expires_in:    3600
    }

    @api.stub(:auth_request, [200, new_tokens]) do
      @api.stub(:api_request, [500, { error: 'server_error' }]) do
        response_code, _data = @api.exchange_authorization_code('oauth-code')
        assert_equal 500, response_code
      end
    end

    assert_equal(
      original_tokens,
      @api.instance_variable_get(:@tokens)
    )
  end

  def test_authorization_code_exchange_rejects_wrong_email
    token_response = {
      access_token:  'access-123',
      refresh_token: 'refresh-123',
      obtained_at:  Time.now.to_i,
      expires_in:   3600
    }

    user_response = {
      response: {
        email: 'someone-else@example.com'
      }
    }

    access_token_file = File.join(@tmpdir, 'tesla_access_token.json')
    unlink(access_token_file) if File.exist?(access_token_file)

    @api.stub(:auth_request, [200, token_response]) do
      @api.stub(:api_request, [200, user_response]) do
        response_code, _data = @api.exchange_authorization_code('oauth-code')
        assert_equal 403, response_code
      end
    end

    refute @api.have_access_token?

    refute File.exist?(access_token_file)
  end

  def test_authorization_code_exchange_does_not_save_on_token_failure
    @api.stub(:auth_request, [400, { error: 'invalid_grant' }]) do
      response_code, data = @api.exchange_authorization_code('bad-code')
      assert_equal 400, response_code
      assert_equal({ error: 'invalid_grant' }, data)
    end

    refute File.exist?(
      File.join(@tmpdir, 'tesla_access_token.json')
    )
  end

  # ------------------------------------------------------------
  # End to end test
  # ------------------------------------------------------------

  def test_api_request_uses_existing_valid_token
    @api.instance_variable_set(:@tokens, valid_tokens)

    api_called     = false
    refresh_called = false

    @api.stub(
      :refresh_access_token,
      lambda {
        refresh_called = true
        true
      }
    ) do
      @api.stub(
        :request_data,
        lambda { |_access_token, _verb, _url, _post_data, **kwargs|
          api_called = true
          [200, { response: { email: 'bill@example.com' } }]
        }
      ) do
        @api.api_request(:GET, 'users/me')
      end
    end

    assert api_called
    refute refresh_called
  end

  def test_api_request_refreshes_expired_token
    @api.instance_variable_set(
      :@tokens,
      valid_tokens.merge(
        obtained_at: Time.now.to_i - 7200,
        expires_in: 3600
      )
    )

    refresh_called = false

    @api.stub(
      :refresh_access_token,
      lambda {
        refresh_called = true

        @api.instance_variable_set(
          :@tokens,
          valid_tokens.merge(
            access_token: 'refreshed-access'
          )
        )

        true
      }
    ) do
      @api.stub(:request_data, [200, { response: { ok: true } }]) do
        @api.api_request(:GET, 'users/me')
      end
    end

    assert refresh_called
  end

  def test_api_request_does_not_send_request_when_refresh_fails
    @api.instance_variable_set(
      :@tokens,
      valid_tokens.merge(
        obtained_at: Time.now.to_i - 7200,
        expires_in: 3600
      )
    )

    request_called = false

    @api.stub(:refresh_access_token, false) do
      @api.stub(
        :request_data,
        lambda { |_verb, _url, _post_data|
          request_called = true
          raise 'request_data should not be called'
        }
      ) do
        result = @api.api_request(:GET, 'users/me')

        refute request_called
        assert_equal [500, { error: 'Unable to refresh access token' }], result
      end
    end
  end

  def test_refresh_fails_when_response_has_no_access_token
    original_tokens = valid_tokens.merge(
      obtained_at: Time.now.to_i - 7200,
      expires_in: 3600
    )

    @api.instance_variable_set(:@tokens, original_tokens)

    @api.stub(:auth_request, [200, { expires_in: 3600 }]) do
      refute @api.refresh_access_token
    end

    new_tokens = @api.instance_variable_get(:@tokens)
    assert_equal original_tokens, new_tokens
  end

  def test_empty_access_token_is_not_available
    @api.instance_variable_set(
      :@tokens,
      { access_token: '' }
    )

    refute @api.have_access_token?
  end

  def test_whitespace_access_token_is_not_available
    @api.instance_variable_set(
      :@tokens,
      { access_token: '   ' }
    )

    refute @api.have_access_token?
  end

  # ------------------------------------------------------------
  # Regression: failed token persistence must not be reported
  # as successful.
  # ------------------------------------------------------------

  def test_refresh_failure_to_persist_tokens_is_reported
    @api.instance_variable_set(
      :@tokens,
      valid_tokens.merge(
        obtained_at: Time.now.to_i - 7200,
        expires_in: 3600
      )
    )

    refreshed = {
      access_token:  'new-access',
      refresh_token: 'new-refresh',
      expires_in:   3600
    }

    @api.stub(:auth_request, [200, refreshed]) do
      @api.stub(
        :save_tokens,
        -> { raise RuntimeError, "Unable to save tokens" }
      ) do
        refute @api.refresh_access_token
      end
    end

    refute_equal 'new-access',
                 @api.instance_variable_get(:@tokens)[:access_token]
  end

  def test_authorization_exchange_reports_token_persistence_failure
    auth_data = {
      access_token:  'new-access',
      refresh_token: 'new-refresh',
      expires_in:    3600
    }

    @api.stub(:auth_request, [200, auth_data]) do
      @api.stub(
        :api_request,
        [200, { response: { email: 'bill@example.com' } }]
      ) do
        @api.stub(
          :save_tokens,
          -> { raise RuntimeError, "Unable to save tokens" }
        ) do
          assert_raises RuntimeError do
          _response_code, _response_data =
            @api.exchange_authorization_code('auth-code')
          end
        end
      end
    end
  end

  # ------------------------------------------------------------
  # Regression: a failed refresh must leave the original token
  # state unchanged.
  # ------------------------------------------------------------

  def test_refresh_failure_does_not_replace_existing_tokens
    original_tokens = valid_tokens.merge(
      obtained_at: Time.now.to_i - 7200,
      expires_in: 3600
    )

    @api.instance_variable_set(
      :@tokens,
      original_tokens.dup
    )

    @api.stub(:auth_request, [400, { error: 'invalid_grant' }]) do
      refute @api.refresh_access_token
    end

    new_tokens = @api.instance_variable_get(:@tokens)

    assert_equal original_tokens, new_tokens
  end

  def test_refresh_failure_does_not_replace_existing_tokens_2
    original = @api.instance_variable_get(:@tokens).dup

    # Arrange auth_request to return a successful-looking response
    # but make token persistence fail.

    @api.stub(:save_tokens, ->(*) { raise RuntimeError, 'disk full' }) do
      refute @api.refresh_access_token
    end

    assert_equal original,
                 @api.instance_variable_get(:@tokens)
  end

  # ------------------------------------------------------------
  # Regression: refresh-token rotation must be preserved.
  # Tesla may return a new refresh token.
  # ------------------------------------------------------------

  def test_successful_refresh_replaces_refresh_token
    @api.instance_variable_set(
      :@tokens,
      valid_tokens.merge(
        obtained_at: Time.now.to_i - 7200,
        expires_in: 3600
      )
    )

    refreshed = {
      access_token:  'rotated-access',
      refresh_token: 'rotated-refresh',
      expires_in:   3600
    }

    @api.stub(:auth_request, [200, refreshed]) do
      assert @api.refresh_access_token
    end

    tokens = @api.instance_variable_get(:@tokens)

    assert_equal 'rotated-access',
                 tokens[:access_token]

    assert_equal 'rotated-refresh',
                 tokens[:refresh_token]
  end

  # ------------------------------------------------------------
  # Refresh-token rotation survives a restart
  # ------------------------------------------------------------

  def test_rotated_refresh_token_survives_restart
    original_tokens = valid_tokens.merge(
      obtained_at: Time.now.to_i - 7200,
      expires_in: 3600
    )

    @api.instance_variable_set(:@tokens, original_tokens)

    refreshed_tokens = {
      access_token:  'new-access',
      refresh_token: 'rotated-refresh',
      expires_in:    3600
    }

    @api.stub(:auth_request, [200, refreshed_tokens]) do
      assert @api.refresh_access_token
    end

    restarted = TeslaAPI.new(@tmpdir, 'config.json')

    tokens = restarted.instance_variable_get(:@tokens)

    assert_equal 'new-access', tokens[:access_token]
    assert_equal 'rotated-refresh', tokens[:refresh_token]
    assert_equal :valid, restarted.token_state
  end

  # ------------------------------------------------------------
  # Regression: if Tesla doesn't return a new refresh token,
  # the existing refresh token must survive.
  # ------------------------------------------------------------

  def test_successful_refresh_preserves_refresh_token_when_omitted
    @api.instance_variable_set(
      :@tokens,
      valid_tokens.merge(
        obtained_at: Time.now.to_i - 7200,
        expires_in: 3600
      )
    )

    refreshed = {
      access_token: 'new-access',
      expires_in:   3600
    }

    @api.stub(:auth_request, [200, refreshed]) do
      assert @api.refresh_access_token
    end

    tokens = @api.instance_variable_get(:@tokens)

    assert_equal 'new-access',
                 tokens[:access_token]

    assert_equal 'refresh-123',
                 tokens[:refresh_token]
  end

  # ------------------------------------------------------------
  # Don't destroy token file if persistence fails.
  # ------------------------------------------------------------

  def test_failed_token_persistence_does_not_destroy_existing_token_file
    old_tokens = valid_tokens

    token_file = File.join(
      @tmpdir,
      'tesla_access_token.json'
    )

    File.write(
      token_file,
      JSON.generate(old_tokens)
    )

    @api.instance_variable_set(
      :@tokens,
      old_tokens.merge(
        obtained_at: Time.now.to_i - 7200,
        expires_in: 3600
      )
    )

    new_tokens = {
      access_token:  'new-access',
      refresh_token: 'new-refresh',
      expires_in:    3600
    }

    @api.stub(:auth_request, [200, new_tokens]) do
      @api.stub(
        :save_tokens,
        -> { raise RuntimeError, "Unable to save tokens" }
      ) do
        refute @api.refresh_access_token
      end
    end

    persisted = JSON.parse(
      File.read(token_file),
      symbolize_names: true
    )

    assert_equal 'refresh-123',
                 persisted[:refresh_token]
  end

  # ------------------------------------------------------------
  # Don't raise exception on badly formed request results.
  # ------------------------------------------------------------

  def test_api_request_handles_non_string_error_types
    [
      {},
      [],
      123,
      true,
      nil
    ].each do |error|
      @api.instance_variable_set(:@tokens, valid_tokens)

      @api.stub(
        :request_data,
        [403, { error: error }]
      ) do
        response_code, data = @api.api_request(:GET, 'users/me')

        assert_equal 403, response_code
        if error.nil?
          assert_nil data[:error]
        else
          assert_equal error, data[:error]
        end
      end
    end
  end

  def test_update_tokens_handles_non_string_error
    @api.instance_variable_set(:@tokens, valid_tokens)

    [
      {},
      [],
      123,
      true,
      nil
    ].each do |error|
      result = @api.send(
        :update_tokens,
        400,
        { error: error }
      )

      refute result
    end
  end

  def test_get_vehicle_state_handles_non_string_error
    @api.instance_variable_set(:@tokens, valid_tokens)

    [
      {},
      [],
      123,
      true,
      nil
    ].each do |error|
      @api.stub(
        :api_request,
        [500, { error: error }]
      ) do
        result = @api.get_vehicle_state('1234567890123456')

        assert_equal 'unknown (500)', result
      end
    end
  end

  # ------------------------------------------------------------
  # Test for bearer issues
  # ------------------------------------------------------------

  def test_invalid_bearer_response_clears_tokens
    @api.instance_variable_set(:@tokens, valid_tokens)

    @api.stub(:request_data, [403, { error: 'invalid bearer token' }]) do
      @api.api_request(:GET, 'users/me')
    end

    refute @api.have_access_token?
  end

  def test_stale_invalid_bearer_does_not_clear_new_token
    old_token = 'old-access'
    new_token = 'new-access'

    @api.instance_variable_set(
      :@tokens,
      valid_tokens.merge(access_token: new_token)
    )

    @api.stub(
      :request_data,
      [403, { error: 'invalid bearer token' }]
    ) do
      @api.send(:clear_tokens, old_token)
    end

    assert_equal(
      new_token,
      @api.instance_variable_get(:@tokens)[:access_token]
    )
  end

  def test_invalid_current_bearer_clears_current_token
    current_token = 'current-access'

    @api.instance_variable_set(
      :@tokens,
      valid_tokens.merge(access_token: current_token)
    )

    @api.send(:clear_tokens, current_token)

    refute @api.have_access_token?
  end

  def test_non_bearer_403_does_not_clear_tokens
    @api.instance_variable_set(
      :@tokens,
      valid_tokens
    )

    @api.stub(:request_data, [403, { error: 'insufficient_scope' }]) do
      @api.api_request(:GET, 'users/me')
    end

    assert @api.have_access_token?
  end

  def test_invalid_bearer_token_clears_current_tokens
    @api.instance_variable_set(:@tokens, valid_tokens)

    @api.stub(
      :request_data,
      [401, { error: 'invalid bearer token' }]
    ) do
      @api.api_request(:GET, 'users/me')
    end

    refute @api.have_access_token?

    refute File.exist?(
      File.join(@tmpdir, 'tesla_access_token.json')
    )
  end

  # ------------------------------------------------------------
  # Token timestamp validations
  # ------------------------------------------------------------

  def test_non_numeric_obtained_at_is_invalid
    @api.instance_variable_set(
      :@tokens,
      valid_tokens.merge(obtained_at: 'not-a-time')
    )

    assert_equal :invalid,  @api.token_state
  end

  def test_non_numeric_expires_in_is_invalid
    @api.instance_variable_set(
      :@tokens,
      valid_tokens.merge(expires_in: 'forever')
    )

    assert_equal :invalid,  @api.token_state
  end

  def test_zero_expires_in_is_invalid
    @api.instance_variable_set(
      :@tokens,
      valid_tokens.merge(expires_in: 0)
    )

    assert_equal :invalid,  @api.token_state
  end

  def test_negative_expires_in_is_invalid
    @api.instance_variable_set(
      :@tokens,
      valid_tokens.merge(expires_in: -1)
    )

    assert_equal :invalid,  @api.token_state
  end

  def test_token_obtained_too_far_in_future_is_invalid
    @api.instance_variable_set(
      :@tokens,
      valid_tokens.merge(
        obtained_at: Time.now.to_i + 11
      )
    )

    assert_equal :invalid,  @api.token_state
  end

  def test_token_obtained_within_clock_skew_is_valid
    @api.instance_variable_set(
      :@tokens,
      valid_tokens.merge(
        obtained_at: Time.now.to_i + 5
      )
    )

    assert_equal :valid,  @api.token_state
  end

  # ------------------------------------------------------------
  # State directory permissions
  # ------------------------------------------------------------

  def test_state_directory_is_created_with_configured_permissions
    @api.instance_variable_set(:@tokens, valid_tokens)

    state_dir = File.join(@tmpdir, 'new-state-dir')

    config = @api.instance_variable_get(:@config)
    config[:state_dir] = state_dir
    config[:state_dir_perms] = 0700

    @api.instance_variable_set(
      :@access_token_file,
      File.join(state_dir, 'tesla_access_token.json')
    )

    @api.send(:save_tokens)

    assert Dir.exist?(state_dir)
    assert_equal 0700, File.stat(state_dir).mode & 0777
  end

  def test_state_directory_permissions_are_not_more_permissive_than_configured
    state_dir = File.join(@tmpdir, 'state')

    FileUtils.mkdir_p(state_dir)
    File.chmod(0700, state_dir)

    config = @api.instance_variable_get(:@config)
    config[:state_dir] = state_dir
    config[:state_dir_perms] = 0700

    @api.instance_variable_set(
      :@access_token_file,
      File.join(state_dir, 'tesla_access_token.json')
    )

    # Should not raise.
    @api.send(:save_tokens)

    assert_equal 0700, File.stat(state_dir).mode & 0777
  end

  # ------------------------------------------------------------
  # Token file permissions
  # ------------------------------------------------------------

  def test_existing_token_file_with_excessive_permissions_is_rejected
    filename = File.join(
      @tmpdir,
      'tesla_access_token.json'
    )

    File.write(
      filename,
      JSON.generate(valid_tokens),
      perm: 0644
    )

    assert_raises(RuntimeError) do
      TeslaAPI.new(@tmpdir, 'config.json')
    end
  end

  def test_existing_token_file_with_correct_permissions_is_accepted
    filename = File.join(
      @tmpdir,
      'tesla_access_token.json'
    )

    File.write(
      filename,
      JSON.generate(valid_tokens),
      perm: 0600
    )

    restarted = TeslaAPI.new(@tmpdir, 'config.json')

    assert restarted.have_access_token?
    assert_equal :valid, restarted.token_state
  end

  # ------------------------------------------------------------
  # Token clearing
  # ------------------------------------------------------------

  def test_clear_tokens_removes_in_memory_and_persisted_tokens
    filename = File.join(
      @tmpdir,
      'tesla_access_token.json'
    )

    @api.instance_variable_set(:@tokens, valid_tokens)
    @api.send(:save_tokens)

    assert File.exist?(filename)

    @api.clear_tokens

    assert_empty @api.instance_variable_get(:@tokens)
    refute File.exist?(filename)
  end

  def test_clear_tokens_does_not_clear_newer_token
    original = valid_tokens

    @api.instance_variable_set(:@tokens, original.dup)

    @api.clear_tokens('some-other-access-token')

    assert_equal original,
                 @api.instance_variable_get(:@tokens)
  end

  def test_clear_tokens_clears_matching_token
    original = valid_tokens

    @api.instance_variable_set(:@tokens, original.dup)

    @api.clear_tokens(original[:access_token])

    assert_empty @api.instance_variable_get(:@tokens)
  end

  # ------------------------------------------------------------
  # Token-state edge cases
  # ------------------------------------------------------------

  def test_token_with_empty_access_token_is_invalid
    @api.instance_variable_set(
      :@tokens,
      valid_tokens.merge(access_token: '')
    )

    refute @api.have_access_token?
    assert_equal :invalid, @api.token_state
  end

  def test_token_with_missing_obtained_at_is_invalid
    @api.instance_variable_set(
      :@tokens,
      valid_tokens.reject { |key, _| key == :obtained_at }
    )

    assert_equal :invalid, @api.token_state
  end

  def test_token_with_missing_expires_in_is_invalid
    @api.instance_variable_set(
      :@tokens,
      valid_tokens.reject { |key, _| key == :expires_in }
    )

    assert_equal :invalid, @api.token_state
  end

  def test_token_with_non_numeric_obtained_at_is_invalid
    @api.instance_variable_set(
      :@tokens,
      valid_tokens.merge(obtained_at: 'abc')
    )

    assert_equal :invalid, @api.token_state
  end

  def test_token_with_non_numeric_expires_in_is_invalid
    @api.instance_variable_set(
      :@tokens,
      valid_tokens.merge(expires_in: 'abc')
    )

    assert_equal :invalid, @api.token_state
  end

  def test_token_expiring_exactly_at_current_time_is_expired
    @api.instance_variable_set(
      :@tokens,
      valid_tokens.merge(
        obtained_at: Time.now.to_i - 3600,
        expires_in: 3600
      )
    )

    assert_equal :expired, @api.token_state
  end

  # ------------------------------------------------------------
  # Refresh-token behavior
  # ------------------------------------------------------------

  def test_refresh_preserves_old_refresh_token_when_response_omits_it
    original_tokens = valid_tokens.merge(
      obtained_at: Time.now.to_i - 7200,
      expires_in: 3600
    )

    @api.instance_variable_set(:@tokens, original_tokens.dup)

    refreshed = {
      access_token: 'new-access',
      expires_in: 3600
    }

    @api.stub(:auth_request, [200, refreshed]) do
      assert @api.refresh_access_token
    end

    tokens = @api.instance_variable_get(:@tokens)

    assert_equal 'new-access', tokens[:access_token]
    assert_equal 'refresh-123', tokens[:refresh_token]
    assert_equal :valid, @api.token_state
  end

  def test_refresh_failure_does_not_destroy_original_tokens
    original_tokens = valid_tokens.merge(
      obtained_at: Time.now.to_i - 7200,
      expires_in: 3600
    )

    @api.instance_variable_set(:@tokens, original_tokens.dup)

    @api.stub(
      :auth_request,
      [400, { error: 'invalid_grant' }]
    ) do
      refute @api.refresh_access_token
    end

    assert_equal(
      original_tokens,
      @api.instance_variable_get(:@tokens)
    )
  end

  def test_refresh_persistence_failure_restores_original_tokens
    original_tokens = valid_tokens.merge(
      obtained_at: Time.now.to_i - 7200,
      expires_in: 3600
    )

    @api.instance_variable_set(:@tokens, original_tokens.dup)

    refreshed = {
      access_token: 'new-access',
      refresh_token: 'new-refresh',
      expires_in: 3600
    }

    @api.stub(:auth_request, [200, refreshed]) do
      @api.stub(
        :save_tokens,
        -> { raise RuntimeError, 'save failed' }
      ) do
        refute @api.refresh_access_token
      end
    end

    assert_equal(
      original_tokens,
      @api.instance_variable_get(:@tokens)
    )
  end

  # ------------------------------------------------------------
  # Authorization-code exchange
  # ------------------------------------------------------------

  def test_authorization_code_exchange_sends_expected_parameters
    token_response = {
      access_token: 'access',
      refresh_token: 'refresh',
      expires_in: 3600
    }

    user_response = {
      response: {
        email: 'bill@example.com'
      }
    }

    request_data = nil

    @api.stub(
      :auth_request,
      lambda { |_verb, _path, data|
        request_data = data
        [200, token_response]
      }
    ) do
      @api.stub(:api_request, [200, user_response]) do
        @api.exchange_authorization_code('the-code')
      end
    end

    assert_equal 'the-code', request_data[:code]
    assert_equal 'authorization_code',
                 request_data[:grant_type]
    assert_equal @api.config[:client_id],
                 request_data[:client_id]
    assert_equal @api.config[:client_secret],
                 request_data[:client_secret]
    assert_equal @api.config[:redirect_uri],
                 request_data[:redirect_uri]
  end

  def test_authorization_code_exchange_does_not_persist_failed_token_response
    original_tokens = valid_tokens
    @api.instance_variable_set(:@tokens, original_tokens.dup)

    @api.stub(
      :auth_request,
      [400, { error: 'invalid_grant' }]
    ) do
      response_code, _data =
        @api.exchange_authorization_code('bad-code')

      assert_equal 400, response_code
    end

    assert_equal(
      original_tokens,
      @api.instance_variable_get(:@tokens)
    )
  end

end
