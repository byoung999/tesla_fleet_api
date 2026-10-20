module Tesla

  # Maps signed-command exceptions to retry-policy categories. Only transport
  # failures are classified as retryable; authentication, TLS, timeout,
  # protocol, and unknown failures are deliberately not retried.
  #
  # @see https://developers.tesla.com/docs/fleet-api

  module ErrorClassifier
    module_function

    # Classifies a signed-command exception into the symbolic category consumed
    # by the retry policy.
    #
    # @param [Exception] error value used by the operation.
    # @return [Symbol] the requested protocol value.

    def classify(error)
      case error
      when Tesla::AuthenticationError
        :authentication

      when Tesla::TLSConnectionError
        :tls

      when Tesla::TimeoutError
        :timeout

      when Tesla::ProtocolError
        :protocol

      when Tesla::TransportError
        :transport

      else
        :unknown
      end
    end

    # Performs the `retryable` operation used by the signed-command protocol
    # implementation.
    #
    # @return [Boolean] the command result or constructed protocol value.

    def retryable?(error)
      case classify(error)
      when :transport
        true
      else
        false
      end
    end
  end
end
