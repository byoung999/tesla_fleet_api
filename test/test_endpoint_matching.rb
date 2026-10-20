# frozen_string_literal: true

require_relative 'test_helper'

class EndpointMatchingTest < TeslaAPITest

  VIN = '5YJ3E1EA7KF000001'

  # ------------------------------------------------------------
  # Basic endpoint matching
  # ------------------------------------------------------------

  def test_matches_users_me
    verb, endpoint = @api.find_endpoint(
      'users/me',
      VIN,
      :GET
    )

    assert_equal :GET, verb
    assert_equal "#{TeslaAPI::API_BASE_PATH}/users/me", endpoint
  end

  def test_accepts_api_1_prefix
    verb, endpoint = @api.find_endpoint(
      "#{TeslaAPI::API_BASE_PATH}/users/me",
      VIN,
      :GET
    )

    assert_equal :GET, verb
    assert_equal "#{TeslaAPI::API_BASE_PATH}/users/me", endpoint
  end

  def test_accepts_full_tesla_url
    assert_raises(RuntimeError) do
      _verb, _endpoint = @api.find_endpoint(
        "https://evil.example#{TeslaAPI::API_BASE_PATH}/users/me",
        VIN,
        :GET
      )
    end
  end

  # ------------------------------------------------------------
  # Vehicle shorthand
  # ------------------------------------------------------------

  def test_expands_vehicle_endpoint_using_vin
    verb, endpoint = @api.find_endpoint(
      'vehicle_data',
      VIN,
      :GET
    )

    assert_equal :GET, verb
    assert_equal(
      "#{TeslaAPI::API_BASE_PATH}/vehicles/#{VIN}/vehicle_data",
      endpoint
    )
  end

  def test_expands_vehicle_data_subrequest
    verb, endpoint = @api.find_endpoint(
      'location_data',
      VIN,
      :GET
    )

    assert_equal :GET, verb
    assert_equal(
      "#{TeslaAPI::API_BASE_PATH}/vehicles/#{VIN}/vehicle_data?endpoints=location_data",
      endpoint
    )
  end

  # ------------------------------------------------------------
  # VIN substitution
  # ------------------------------------------------------------

  def test_substitutes_vin_into_endpoint
    verb, endpoint = @api.find_endpoint(
      'vehicles/{vin}/vehicle_data',
      VIN,
      :GET
    )

    assert_equal :GET, verb
    assert_equal(
      "#{TeslaAPI::API_BASE_PATH}/vehicles/#{VIN}/vehicle_data",
      endpoint
    )
  end

  def test_adds_vin_to_endpoint_that_requires_it
    verb, endpoint = @api.find_endpoint(
      'dx/vehicles/subscriptions/eligibility',
      VIN,
      :GET
    )

    assert_equal :GET, verb
    assert_equal(
      "#{TeslaAPI::API_BASE_PATH}/dx/vehicles/subscriptions/eligibility?vin=#{VIN}",
      endpoint
    )
  end

  # ------------------------------------------------------------
  # VIN-required endpoints
  # ------------------------------------------------------------

  def test_vin_required_endpoint_rejects_missing_vehicle_id
    error = assert_raises(RuntimeError) do
      @api.find_endpoint(
        'dx/vehicles/options',
        nil,
        :GET
      )
    end

    assert_match(/Invalid endpoint|Invalid vehicle ID/, error.message)
  end

  def test_vin_required_endpoint_rejects_empty_vehicle_id
    error = assert_raises(RuntimeError) do
      @api.find_endpoint(
        'dx/vehicles/options',
        '',
        :GET
      )
    end

    assert_match(/Invalid endpoint|Invalid vehicle ID/, error.message)
  end

  def test_vin_required_endpoint_accepts_valid_vehicle_id
    verb, endpoint = @api.find_endpoint(
      'dx/vehicles/options',
      VIN,
      :GET
    )

    assert_equal :GET, verb
    assert_equal(
      "#{TeslaAPI::API_BASE_PATH}/dx/vehicles/options?vin=#{VIN}",
      endpoint
    )
  end

  def test_explicit_vin_must_match_requested_vehicle_id
    other_vin = '5YJ3E1EA7KF000002'

    error = assert_raises(RuntimeError) do
      @api.find_endpoint(
        "dx/vehicles/options?vin=#{other_vin}",
        VIN,
        :GET
      )
    end

    assert_match(/Invalid endpoint/, error.message)
  end

  # ------------------------------------------------------------
  # Vehicle ID validation
  # ------------------------------------------------------------

  def test_rejects_vehicle_id_with_slash
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'vehicle_data',
        "#{VIN}/evil",
        :GET
      )
    end
  end

  def test_rejects_vehicle_id_with_backslash
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'vehicle_data',
        "#{VIN}\\evil",
        :GET
      )
    end
  end

  def test_rejects_vehicle_id_with_question_mark
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'vehicle_data',
        "#{VIN}?evil",
        :GET
      )
    end
  end

  def test_rejects_vehicle_id_with_fragment
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'vehicle_data',
        "#{VIN}#evil",
        :GET
      )
    end
  end

  def test_rejects_vehicle_id_with_percent_encoding
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'vehicle_data',
        "#{VIN}%2Fevil",
        :GET
      )
    end
  end

  def test_rejects_vehicle_id_with_whitespace
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'vehicle_data',
        "#{VIN} evil",
        :GET
      )
    end
  end

  # ------------------------------------------------------------
  # Host validation
  # ------------------------------------------------------------

  def test_rejects_untrusted_absolute_url
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        "https://evil.example#{TeslaAPI::API_BASE_PATH}/vehicles/#{VIN}",
        VIN,
        :GET
      )
    end
  end

  def test_rejects_untrusted_host_without_scheme
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        "evil.example#{TeslaAPI::API_BASE_PATH}/vehicles/#{VIN}",
        VIN,
        :GET
      )
    end
  end

  # ------------------------------------------------------------
  # Path traversal
  # ------------------------------------------------------------

  def test_rejects_encoded_dot_component
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'energy_sites/%2e/vehicles',
        VIN,
        :GET
      )
    end
  end

  def test_rejects_encoded_backslash
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        "energy_sites/%5c%5c/vehicles/#{VIN}",
        VIN,
        :GET
      )
    end
  end

  def test_rejects_path_with_backslash
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        "energy_sites/..\\vehicles/#{VIN}",
        VIN,
        :GET
      )
    end
  end

  # ------------------------------------------------------------
  # Query parameters
  # ------------------------------------------------------------

  def test_extra_query_parameters_are_preserved
    _verb, endpoint = @api.find_endpoint(
      "vehicles/#{VIN}/vehicle_data?foo=bar&another=value",
      VIN,
      :GET
    )

    uri = URI(endpoint)
    query = Rack::Utils.parse_nested_query(uri.query)

    assert_equal 'bar',   query['foo']
    assert_equal 'value', query['another']
  end

  def test_required_constant_query_parameter_must_match
    error = assert_raises(RuntimeError) do
      @api.find_endpoint(
        'energy_sites/123/calendar_history?' \
        'kind=wrong&' \
        'start_date=2023-01-01T00:00:00-08:00&' \
        'end_date=2023-12-31:23:59-08:00&' \
        'period=year&' \
        'time_zone=America/Los_Angeles',
        VIN,
        :GET
      )
    end

    assert_match(/Invalid endpoint/, error.message)
  end

  def test_required_query_parameter_cannot_be_omitted
    error = assert_raises(RuntimeError) do
      @api.find_endpoint(
        'energy_sites/123/calendar_history?' \
        'kind=backup&' \
        'start_date=2023-01-01T00:00:00-08:00&' \
        'end_date=2023-12-31:23:59-08:00&' \
        'period=year',
        VIN,
        :GET
      )
    end

    assert_match(/Invalid endpoint/, error.message)
  end

  # ------------------------------------------------------------
  # HTTP methods
  # ------------------------------------------------------------

  def test_post_endpoint_is_selected_for_get_request_when_no_get_exists
    verb, endpoint = @api.find_endpoint(
      "vehicles/#{VIN}/wake_up",
      VIN,
      :GET
    )

    assert_equal :POST, verb
    assert_equal(
      "#{TeslaAPI::API_BASE_PATH}/vehicles/#{VIN}/wake_up",
      endpoint
    )
  end

  def test_get_endpoint_is_not_replaced_by_post_endpoint
    verb, endpoint = @api.find_endpoint(
      "vehicles/#{VIN}",
      VIN,
      :GET
    )

    assert_equal :GET, verb
    assert_equal(
      "#{TeslaAPI::API_BASE_PATH}/vehicles/#{VIN}",
      endpoint
    )
  end

  # ------------------------------------------------------------
  # Endpoint-definition integrity
  # ------------------------------------------------------------

  def test_endpoint_definitions_do_not_contain_duplicate_verb_and_path
    duplicates =
      TeslaAPI::ENDPOINTS
        .group_by { |endpoint| [endpoint[:verb], endpoint[:endpoint]] }
        .select { |_key, definitions| definitions.length > 1 }

    assert_empty duplicates,
                 "Duplicate endpoint definitions: #{duplicates.keys.inspect}"
  end

  # ------------------------------------------------------------
  # Query parameters
  # ------------------------------------------------------------

  def test_preserves_endpoint_query_parameters
    verb, endpoint = @api.find_endpoint(
      'dx/vehicles/options?vin=' + VIN,
      VIN,
      :GET
    )

    assert_equal :GET, verb
    assert_equal(
      "#{TeslaAPI::API_BASE_PATH}/dx/vehicles/options?vin=#{VIN}",
      endpoint
    )
  end

  def test_url_query_parameters_are_preserved
    _verb, endpoint = @api.find_endpoint(
      'vehicles/' + VIN + '/vehicle_data?foo=bar',
      VIN,
      :GET
    )

    assert_equal(
      "#{TeslaAPI::API_BASE_PATH}/vehicles/#{VIN}/vehicle_data?foo=bar",
      endpoint
    )
  end

  def test_url_query_parameters_differentiating_endpoint
    _verb, endpoint = @api.find_endpoint(
      'energy_sites/123/calendar_history?kind=backup&start_date=2023-01-01T00:00:00-08:00&end_date=2023-12-31:23:59-08:00&period=year&time_zone=America/Los_Angeles',
      VIN,
      :GET
    )

    assert_equal(
      "#{TeslaAPI::API_BASE_PATH}/energy_sites/123/calendar_history?kind=backup&start_date=2023-01-01T00%3A00%3A00-08%3A00&end_date=2023-12-31%3A23%3A59-08%3A00&period=year&time_zone=America%2FLos_Angeles",
      endpoint
    )

    _verb, endpoint = @api.find_endpoint(
      'energy_sites/123/calendar_history?kind=energy&start_date=2023-01-01T00:00:00-08:00&end_date=2023-12-31:23:59-08:00&period=year&time_zone=America/Los_Angeles',
      VIN,
      :GET
    )

    assert_equal(
      "#{TeslaAPI::API_BASE_PATH}/energy_sites/123/calendar_history?kind=energy&start_date=2023-01-01T00%3A00%3A00-08%3A00&end_date=2023-12-31%3A23%3A59-08%3A00&period=year&time_zone=America%2FLos_Angeles",
      endpoint
    )
  end

  def test_url_query_parameters_missing_required_parameter
    error = assert_raises(RuntimeError) do
      _verb, _endpoint = @api.find_endpoint(
        'energy_sites/123/calendar_history?kind=backup&start_date=2023-01-01T00:00:00-08:00&end_date=2023-12-31:23:59-08:00&period=year',
        VIN,
        :GET
      )
    end

    assert_match(/Invalid endpoint/, error.message)
  end

  def test_rejects_dot_dot_path_component
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'energy_sites/../vehicles/' + VIN,
        VIN,
        :GET
      )
    end
  end

  def test_rejects_encoded_dot_dot_path_component
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'energy_sites/%2e%2e/vehicles/' + VIN,
        VIN,
        :GET
      )
    end
  end

  # ------------------------------------------------------------
  # HTTP verb handling
  # ------------------------------------------------------------

  def test_get_vehicle_endpoint_does_not_match_post
    verb, endpoint = @api.find_endpoint(
      'vehicles/' + VIN,
      VIN,
      :GET
    )

    assert_equal :GET, verb
    assert_equal "#{TeslaAPI::API_BASE_PATH}/vehicles/#{VIN}", endpoint
  end

  def test_wake_up_falls_back_to_post
    verb, endpoint = @api.find_endpoint(
      'vehicles/' + VIN + '/wake_up',
      VIN,
      :GET
    )

    assert_equal :POST, verb
    assert_equal(
      "#{TeslaAPI::API_BASE_PATH}/vehicles/#{VIN}/wake_up",
      endpoint
    )
  end

  def test_process_endpoints_uses_get_without_post_data
    requests = []

    @api.stub(
      :api_request,
      lambda { |verb, endpoint, post_data = nil|
        requests << [verb, endpoint, post_data]
        [200, {}]
      }
    ) do
      @api.process_endpoints(
        ['vehicles'],
        nil,
        nil
      )
    end

    assert_equal :GET, requests.first[0]
    assert_nil requests.first[2]
  end

  def test_process_endpoints_uses_post_with_post_data
    requests = []

    @api.stub(
      :api_request,
      lambda { |verb, endpoint, post_data = nil|
        requests << [verb, endpoint, post_data]
        [200, {}]
      }
    ) do
      @api.process_endpoints(
        ['partner_accounts'],
        nil,
        { foo: 'bar' }
      )
    end

    assert_equal :POST, requests.first[0]
    assert_equal({ foo: 'bar' }, requests.first[2])
  end

  def test_process_endpoints_empty_post_data_still_uses_post
    requests = []

    @api.stub(
      :api_request,
      lambda { |verb, endpoint, post_data = nil|
        requests << [verb, endpoint, post_data]
        [200, {}]
      }
    ) do
      @api.process_endpoints(
        ['partner_accounts'],
        nil,
        {}
      )
    end

    assert_equal :POST, requests.first[0]
  end

  # ------------------------------------------------------------
  # Invalid endpoints
  # ------------------------------------------------------------

  def test_rejects_unknown_endpoint
    error = assert_raises(RuntimeError) do
      @api.find_endpoint(
        'vehicles/' + VIN + '/does_not_exist',
        VIN,
        :GET
      )
    end

    assert_match(/Invalid endpoint/, error.message)
  end

  def test_rejects_malformed_endpoint
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        '%',
        VIN,
        :GET
      )
    end
  end

  def test_endpoint_definitions_do_not_contain_duplicates
    duplicates =
      TeslaAPI::ENDPOINTS
        .group_by { |endpoint| [endpoint[:verb], endpoint[:endpoint]] }
        .select { |_key, definitions| definitions.length > 1 }

    assert_empty duplicates,
                 "Duplicate endpoint definitions: #{duplicates.keys.inspect}"
  end

  # ------------------------------------------------------------
  # Host stripping
  # ------------------------------------------------------------

  def test_full_url_host_is_not_used
    assert_raises(RuntimeError) do
      _verb, _endpoint = @api.find_endpoint(
        'https://attacker.example/vehicles/' + VIN,
        VIN,
        :GET
      )
    end
  end

# ------------------------------------------------------------
# Vehicle ID / VIN validation
# ------------------------------------------------------------

  def test_rejects_nil_vehicle_id_for_vehicle_endpoint
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'vehicles/{vin}/vehicle_data',
        nil,
        :GET
      )
    end
  end

  def test_rejects_vehicle_id_containing_slash
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'vehicles/{vin}/vehicle_data',
        '12345/evil',
        :GET
      )
    end
  end

  def test_rejects_vehicle_id_containing_question_mark
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'vehicles/{vin}/vehicle_data',
        '12345?foo=bar',
        :GET
      )
    end
  end

  def test_rejects_vehicle_id_containing_fragment
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'vehicles/{vin}/vehicle_data',
        '12345#evil',
        :GET
      )
    end
  end

  def test_rejects_vehicle_id_containing_whitespace
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'vehicles/{vin}/vehicle_data',
        '12345 678',
        :GET
      )
    end
  end

  def test_rejects_vehicle_id_containing_percent_encoding
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'vehicles/{vin}/vehicle_data',
        '12345%2Fevil',
        :GET
      )
    end
  end

  def test_accepts_normal_vehicle_id
    verb, endpoint = @api.find_endpoint(
      'vehicles/{vin}/vehicle_data',
      '12345',
      :GET
    )

    assert_equal :GET, verb
    assert_equal(
      "#{TeslaAPI::API_BASE_PATH}/vehicles/12345/vehicle_data",
      endpoint
    )
  end

  def test_rejects_empty_vehicle_id
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'vehicles/{vin}/vehicle_data',
        '',
        :GET
      )
    end
  end

  def test_rejects_vehicle_id_containing_backslash
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'vehicles/{vin}/vehicle_data',
        '12345\\evil',
        :GET
      )
    end
  end

  def test_rejects_vehicle_id_containing_percent_encoded_backslash
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'vehicles/{vin}/vehicle_data',
        '12345%5Cevil',
        :GET
      )
    end
  end

  # ------------------------------------------------------------
  # Parameter tests
  # ------------------------------------------------------------

  def test_path_parameter_cannot_contain_slash
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'energy_sites/123/evil/backup',
        '12345',
        :POST
      )
    end
  end

  def test_path_parameter_cannot_escape_endpoint
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'vehicles/12345/invitations/abc/evil/revoke',
        '12345',
        :POST
      )
    end
  end

  def test_required_query_parameters_cannot_be_omitted
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'energy_sites/123/calendar_history?kind=backup',
        '12345',
        :GET
      )
    end
  end

  def test_wrong_constant_query_parameter_does_not_match
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'energy_sites/123/calendar_history?kind=bogus&' \
        'start_date=2023-01-01&end_date=2023-12-31&' \
        'period=year&time_zone=America/Los_Angeles',
        '12345',
        :GET
      )
    end
  end

  def test_rejects_encoded_slash_in_dynamic_path_parameter
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'energy_sites/123%2Fevil/live_status',
        VIN,
        :GET
      )
    end
  end

  def test_rejects_encoded_backslash_in_dynamic_path_parameter
    assert_raises(RuntimeError) do
      @api.find_endpoint(
        'energy_sites/123%5Cevil/live_status',
        VIN,
        :GET
      )
    end
  end

end
