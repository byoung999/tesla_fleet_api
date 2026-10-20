require_relative "../test_helper"

class TestErrorClassifier < Minitest::Test
  def test_protocol_errors_are_not_retryable
    error = Tesla::ProtocolError.new("bad response")

    assert_equal(
      :protocol,
      Tesla::ErrorClassifier.classify(error)
    )

    refute(
      Tesla::ErrorClassifier.retryable?(error)
    )
  end

  def test_timeout_is_not_retryable
    error = Tesla::TimeoutError.new("timeout")

    assert_equal(
      :timeout,
      Tesla::ErrorClassifier.classify(error)
    )

    refute(
      Tesla::ErrorClassifier.retryable?(error)
    )
  end

  def test_transport_error_is_retryable
    error = Tesla::TransportError.new("connection failed")

    assert_equal(
      :transport,
      Tesla::ErrorClassifier.classify(error)
    )

    assert(
      Tesla::ErrorClassifier.retryable?(error)
    )
  end

  def test_authentication_error_is_not_retryable
    error = Tesla::AuthenticationError.new("authentication failed")

    assert_equal(
      :authentication,
      Tesla::ErrorClassifier.classify(error)
    )

    refute(
      Tesla::ErrorClassifier.retryable?(error)
    )
  end

  def test_authentication_error_is_classified_as_authentication
    error =
      Tesla::AuthenticationError.new(
        "invalid session info authentication tag"
      )

    assert_equal(
      :authentication,
      Tesla::ErrorClassifier.classify(error)
    )
  end

end
