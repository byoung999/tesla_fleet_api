require "json"
require "cgi"

require_relative "errors"

module Tesla

  # Small adapter around TeslaAPI that submits an encoded RoutableMessage to
  # the Fleet API signed-command endpoint and translates non-success HTTP
  # responses into FleetAPIError.
  #
  # @see https://developers.tesla.com/docs/fleet-api

  class FleetTransport
    DEFAULT_OPEN_TIMEOUT  = 10
    DEFAULT_READ_TIMEOUT  = 30
    DEFAULT_WRITE_TIMEOUT = 30

    attr_reader \
      :open_timeout,
      :read_timeout,
      :write_timeout

    # Creates a Fleet transport with optional TeslaAPI and network-timeout
    # dependencies. Omitted timeouts use the class defaults.
    #
    # @return [void] the operation result.

    def initialize(
      tesla_api:     nil,
      open_timeout:  nil,
      read_timeout:  nil,
      write_timeout: nil
    )
      @tesla_api     = tesla_api
      @open_timeout  = open_timeout.nil?  ? DEFAULT_OPEN_TIMEOUT  : open_timeout
      @read_timeout  = read_timeout.nil?  ? DEFAULT_READ_TIMEOUT  : read_timeout
      @write_timeout = write_timeout.nil? ? DEFAULT_WRITE_TIMEOUT : write_timeout
    end

    # POSTs an encoded RoutableMessage to the Fleet API
    # `vehicles/:vin/signed_command` endpoint. The VIN is URI-escaped,
    # configured network timeouts are passed through, and any non-200 response
    # raises FleetAPIError containing the HTTP status and response body.
    #
    # @return [Hash] the command result or constructed protocol value.

    def signed_command(
      vin:,
      routable_message:
    )
      post_data = { "routable_message" => routable_message }
      (response_code, response_body) = @tesla_api.api_request(
        :POST,
        "vehicles/#{CGI.escapeURIComponent(vin)}/signed_command",
        post_data,
        open_timeout:  @open_timeout,
        read_timeout:  @read_timeout,
        write_timeout: @write_timeout
      )

      unless response_code == 200
        raise Tesla::FleetAPIError.new(
          status: response_code,
          body:   response_body
        )
      end

      response_body = {} if response_body.nil?

      response_body
    end
  end

  # Represents a non-success HTTP response from the Tesla Fleet API
  # signed-command endpoint while preserving the HTTP status and response body.
  #
  # @see https://developers.tesla.com/docs/fleet-api

  class FleetAPIError < Tesla::TransportError
    attr_reader :status, :body

    # Creates a Fleet transport with optional TeslaAPI and network-timeout
    # dependencies. Omitted timeouts use the class defaults.
    #
    # @param [Integer, nil] status value used by the operation.
    # @param [Hash, nil] body value used by the operation.
    # @param [String, nil] message value used by the operation.
    # @return [void] the operation result.

    def initialize(status: nil, body: nil, message: nil)
      @status = status
      @body   = body

      super(message || "Tesla Fleet API request failed (HTTP #{status})")
    end
  end
end
