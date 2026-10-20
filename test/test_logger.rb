require_relative "test_helper"
require "stringio"
require "logger"

class TestTeslaSafeLogger < Minitest::Test
  def setup
    @output = StringIO.new
    @logger = Logger.new(@output)

    @safe_logger =
      Tesla::SafeLogger.new(@logger)
  end

  def test_logs_event
    @safe_logger.info(
      "command_start",
      action: "lock"
    )

    output = @output.string

    assert_includes(
      output,
      "command_start"
    )

    assert_includes(
      output,
      "lock"
    )
  end

  def test_does_not_log_session_key_when_not_supplied
    secret = "a" * 32

    @safe_logger.info(
      "session_restored",
      counter: 10
    )

    refute_includes(
      @output.string,
      secret
    )
  end

  def test_exception_does_not_log_exception_message
    error =
      Tesla::ProtocolError.new(
        "secret-value-must-not-be-logged"
      )

    @safe_logger.error(
      "command_failed",
      error: error
    )

    output = @output.string

    assert_includes(
      output,
      "Tesla::ProtocolError"
    )

    refute_includes(
      output,
      "secret-value-must-not-be-logged"
    )
  end

end
