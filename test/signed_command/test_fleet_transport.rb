require "minitest/autorun"
require "json"
require "net/http"

require "test_helper"
require "TeslaAPI"
require "fleet_transport"

class FakeTeslaAPI
  attr_reader :calls

  def initialize(response: [200, { "response" => "ok" }])
    @response = response
    @calls = []
  end

  def api_request(
    verb,
    path,
    post_data = nil,
    open_timeout: nil,
    read_timeout: nil,
    write_timeout: nil
  )
    @calls << {
      verb: verb,
      path: path,
      post_data: post_data,
      open_timeout: open_timeout,
      read_timeout: read_timeout,
      write_timeout: write_timeout
    }

    @response
  end
end

class TestFleetTransport < Minitest::Test

  def test_fleet_api_error_is_a_transport_error
    error =
      Tesla::FleetAPIError.new(
        status: 503,
        body: { "error" => "service unavailable" }
      )

    assert_kind_of(
      Tesla::TransportError,
      error
    )
  end

  def test_fleet_api_error_is_classified_as_transport
    error =
      Tesla::FleetAPIError.new(
        status: 503
      )

    assert_equal(
      :transport,
      Tesla::ErrorClassifier.classify(error)
    )
  end

  def test_fleet_api_error_is_retryable
    error =
      Tesla::FleetAPIError.new(
        status: 503
      )

    assert(
      Tesla::ErrorClassifier.retryable?(error)
    )
  end

  def test_signed_command
    tesla_api = FakeTeslaAPI.new(
      response: [200, { "response" => "ok" }]
    )

    transport = build_transport(tesla_api: tesla_api)

    result = transport.signed_command(
      vin: "TESTVIN",
      routable_message: "abc123"
    )

    assert_equal(
      { "response" => "ok" },
      result
    )

    assert_equal 1, tesla_api.calls.length

    call = tesla_api.calls.first

    assert_equal :POST, call[:verb]

    assert_equal(
      "vehicles/TESTVIN/signed_command",
      call[:path]
    )

    assert_equal(
      { "routable_message" => "abc123" },
      call[:post_data]
    )

    assert_equal 10, call[:open_timeout]
    assert_equal 30, call[:read_timeout]
    assert_equal 30, call[:write_timeout]
  end

  def test_signed_command_raises_for_http_error
    tesla_api = FakeTeslaAPI.new(
      response: [
        401,
        { "error" => "unauthorized" }
      ]
    )

    transport = build_transport(tesla_api: tesla_api)

    error = assert_raises(Tesla::FleetAPIError) do
      transport.signed_command(
        vin: "TESTVIN",
        routable_message: "abc123"
      )
    end

    assert_equal 401, error.status
    assert_equal(
      { "error" => "unauthorized" },
      error.body
    )
  end

  def test_signed_command_uses_tesla_api
    tesla_api = FakeTeslaAPI.new(
      response: [200, { response: "ok" }]
    )

    transport = build_transport(tesla_api: tesla_api)

    transport.signed_command(
      vin: "TESTVIN",
      routable_message: "abc123"
    )

    assert_equal 1, tesla_api.calls.length
  end

  def test_signed_command_returns_parsed_error_body_from_tesla_api
    tesla_api = FakeTeslaAPI.new(
      response: [
        200,
        { error: "Unable to parse response" }
      ]
    )

    transport = build_transport(tesla_api: tesla_api)

    # FleetTransport currently only checks the HTTP status.
    result = transport.signed_command(
      vin: "TESTVIN",
      routable_message: "abc123"
    )

    assert_equal(
      { error: "Unable to parse response" },
      result
    )
  end

  def test_signed_command_converts_nil_response_body_to_empty_hash
    tesla_api = FakeTeslaAPI.new(
      response: [200, nil]
    )

    transport = build_transport(tesla_api: tesla_api)

    result = transport.signed_command(
      vin: "TESTVIN",
      routable_message: "abc123"
    )

    assert_equal({}, result)
  end

  def test_signed_command_raises_for_http_error_with_nil_body
    tesla_api = FakeTeslaAPI.new(
      response: [500, nil]
    )

    transport = build_transport(tesla_api: tesla_api)

    error = assert_raises(Tesla::FleetAPIError) do
      transport.signed_command(
        vin: "TESTVIN",
        routable_message: "abc123"
      )
    end

    assert_equal 500, error.status
    assert_nil error.body
  end

  def test_signed_command_passes_configured_timeouts_to_tesla_api
    tesla_api = FakeTeslaAPI.new(
      response: [200, { response: "ok" }]
    )

    transport = build_transport(
      tesla_api: tesla_api,
      open_timeout: 5,
      read_timeout: 15,
      write_timeout: 20
    )

    transport.signed_command(
      vin: "TESTVIN",
      routable_message: "abc123"
    )

    assert_equal 1, tesla_api.calls.length

    call = tesla_api.calls.first

    assert_equal 5, call[:open_timeout]
    assert_equal 15, call[:read_timeout]
    assert_equal 20, call[:write_timeout]
  end

  def test_signed_command_url_encodes_vin
    tesla_api = FakeTeslaAPI.new(
      response: [200, { response: "ok" }]
    )

    transport = build_transport(tesla_api: tesla_api)

    transport.signed_command(
      vin: "ABC/123",
      routable_message: "abc123"
    )

    assert_equal 1, tesla_api.calls.length

    call = tesla_api.calls.first

    assert_equal(
      "vehicles/ABC%2F123/signed_command",
      call[:path]
    )
  end

  def test_open_timeout_is_configured
    transport =
      Tesla::FleetTransport.new(
        tesla_api: FakeTeslaAPI.new,
        open_timeout: 3,
        read_timeout: 7,
        write_timeout: 9
      )

    assert_equal(
      3,
      transport.open_timeout
    )

    assert_equal(
      7,
      transport.read_timeout
    )

    assert_equal(
      9,
      transport.write_timeout
    )
  end
  def test_signed_command_passes_default_timeouts_to_tesla_api
    tesla_api =
      FakeTeslaAPI.new(
        response: [200, { response: "ok" }]
      )

    transport =
      Tesla::FleetTransport.new(
        tesla_api: tesla_api
      )

    transport.signed_command(
      vin: "TESTVIN",
      routable_message: "abc123"
    )

    call = tesla_api.calls.first

    assert_equal 10, call[:open_timeout]
    assert_equal 30, call[:read_timeout]
    assert_equal 30, call[:write_timeout]
  end

  def test_signed_command_passes_nil_timeout_values_when_explicitly_disabled
    tesla_api =
      FakeTeslaAPI.new(
        response: [200, { response: "ok" }]
      )

    transport =
      Tesla::FleetTransport.new(
        tesla_api: tesla_api,
        open_timeout: nil,
        read_timeout: nil,
        write_timeout: nil
      )

    transport.signed_command(
      vin: "TESTVIN",
      routable_message: "abc123"
    )

    call = tesla_api.calls.first

    assert_equal 10, call[:open_timeout]
    assert_equal 30, call[:read_timeout]
    assert_equal 30, call[:write_timeout]
  end

  private

  def build_transport(
    tesla_api: FakeTeslaAPI.new,
    open_timeout: nil,
    read_timeout: nil,
    write_timeout: nil
  )
    Tesla::FleetTransport.new(
      tesla_api: tesla_api,
      open_timeout: open_timeout,
      read_timeout: read_timeout,
      write_timeout: write_timeout
    )
  end

  def test_fleet_api_error_accepts_body_without_retaining_it
    body = {
      "error" => "sensitive response",
      "token" => "secret-token"
    }

    error =
      Tesla::FleetAPIError.new(
        status: 500,
        body: body
      )

    assert_equal(500, error.status)

    refute_respond_to(error, :body)
    refute(
      error.instance_variables.include?(:@body),
      "FleetAPIError should not retain the complete response body"
    )
  end

  def test_fleet_api_error_does_not_retain_response_body
    error =
      Tesla::FleetAPIError.new(
        status: 500,
        body: {
          "token" => "secret-token"
        }
      )

    refute(
      error.instance_variable_defined?(:@body)
    )
  end

end
