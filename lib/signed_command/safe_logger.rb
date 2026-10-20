require "logger"

module Tesla

  # Logging facade that removes credentials and other sensitive values before
  # forwarding structured events to Ruby Logger. Exception objects are
  # represented by class name rather than their potentially sensitive messages.
  #
  # @see https://developers.tesla.com/docs/fleet-api

  class SafeLogger
    LEVELS = {
      debug: Logger::DEBUG,
      info: Logger::INFO,
      warn: Logger::WARN,
      error: Logger::ERROR
    }.freeze

    SENSITIVE_KEYS = %i[
      access_token
      authorization
      client_secret
      password
      pin
      private_key
      session_key
      token
    ].freeze

    # Wraps an existing Ruby Logger or creates a stderr logger and assigns the
    # stable `tesla` program name.
    #
    # @param [Logger, nil] logger value used by the operation.
    # @return [void] the operation result.

    def initialize(logger = nil)
      @logger = logger || Logger.new($stderr)
      @logger.progname = "tesla"
    end

    # Logs a debug event after sanitizing all structured fields.
    #
    # @param [Symbol, String] event value used by the operation.
    # @param [Hash{Symbol => Object}] fields value used by the operation.
    # @return [void] the command result or constructed protocol value.

    def debug(event, fields = {})
      write(:debug, event, fields)
    end

    # Logs an informational event after sanitizing all structured fields.
    #
    # @param [Symbol, String] event value used by the operation.
    # @param [Hash{Symbol => Object}] fields value used by the operation.
    # @return [void] the command result or constructed protocol value.

    def info(event, fields = {})
      write(:info, event, fields)
    end

    # Logs a warning event after sanitizing all structured fields.
    #
    # @param [Symbol, String] event value used by the operation.
    # @param [Hash{Symbol => Object}] fields value used by the operation.
    # @return [void] the command result or constructed protocol value.

    def warn(event, fields = {})
      write(:warn, event, fields)
    end

    # Logs an error event after sanitizing all structured fields.
    #
    # @param [Symbol, String] event value used by the operation.
    # @param [Hash{Symbol => Object}] fields value used by the operation.
    # @return [void] the command result or constructed protocol value.

    def error(event, fields = {})
      write(:error, event, fields)
    end

    private

    # Builds the final log message after sanitizing every field, then emits it
    # at the requested Ruby Logger level. Sensitive field names are redacted
    # before formatting.
    #
    # @param [Symbol] level value used by the operation.
    # @param [Symbol, String] event value used by the operation.
    # @param [Hash{Symbol => Object}] fields value used by the operation.
    # @return [void] the operation result.

    def write(level, event, fields)
      safe_fields =
        fields.each_with_object({}) do |(key, value), result|
          result[key] = sanitize_field(key, value)
        end

      message =
        if safe_fields.empty?
          event.to_s
        else
          "#{event} #{safe_fields.inspect}"
        end

      @logger.add(LEVELS.fetch(level), message)
    end

    # Redacts values whose keys identify credentials or key material; all other
    # values are passed through the generic sanitizer.
    #
    # @param [Symbol, String] key value used by the operation.
    # @param [Object] value value to sanitize; arbitrary objects are reduced to a safe representation.
    # @return [String, Symbol, Numeric, TrueClass, FalseClass, NilClass, Hash] sanitized value suitable for logging.

    def sanitize_field(key, value)
      return "[REDACTED]" if SENSITIVE_KEYS.include?(key.to_sym)
      sanitize(value)
    end

    # Converts potentially unsafe objects into log-safe representations.
    # Exceptions are reduced to their class name so exception messages cannot
    # leak secrets.
    #
    # @param [Object] value value to sanitize; arbitrary objects are reduced to a safe representation.
    # @return [String, Symbol, Numeric, TrueClass, FalseClass, NilClass, Hash] sanitized value suitable for logging.

    def sanitize(value)
      case value
      when Symbol, String, Numeric, TrueClass, FalseClass, NilClass
        value
      when Exception
        { class: value.class.name }
      else
        value.class.name
      end
    end
  end
end
