module Tesla

  # Base exception for failures raised by the Tesla signed-command implementation.
  #
  # @see https://developers.tesla.com/docs/fleet-api

  class Error < StandardError
  end

  # Indicates that a vehicle or protocol message violated the signed-command
  # protocol and should not be treated as a transient network failure.
  #
  # @see https://developers.tesla.com/docs/fleet-api

  class ProtocolError < Error
  end

  # Indicates that cryptographic authentication of a signed-command message or
  # response failed.
  #
  # @see https://developers.tesla.com/docs/fleet-api

  class AuthenticationError < Error
  end

  # Base exception for failures while submitting or receiving a signed command
  # over the Fleet transport.
  #
  # @see https://developers.tesla.com/docs/fleet-api

  class TransportError < Error
  end

  # Indicates that the TLS connection could not be established or
  # authenticated. This is deliberately separate from generic transport
  # failures so callers do not accidentally retry a TLS trust failure.
  #
  # @see https://developers.tesla.com/docs/fleet-api

  class TLSConnectionError < TransportError
  end

  # Indicates that a signed-command transport operation exceeded its configured
  # timeout.
  #
  # @see https://developers.tesla.com/docs/fleet-api

  class TimeoutError < TransportError
  end

  # Marker exception for failures that the command layer is explicitly allowed
  # to retry.
  #
  # @see https://developers.tesla.com/docs/fleet-api

  class RetryableError < TransportError
  end

  # Marker exception for failures that must not be retried automatically.
  #
  # @see https://developers.tesla.com/docs/fleet-api

  class NonRetryableError < Error
  end
end
