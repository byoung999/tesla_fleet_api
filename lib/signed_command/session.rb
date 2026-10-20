require "securerandom"
require "time"

require_relative "crypto"

module Tesla

  # In-memory representation of a Tesla signed-command session, including the
  # derived session key, vehicle public key, epoch, counter, vehicle clock
  # offset, and routing address. The class enforces monotonic clock and counter
  # updates and validates persisted state before restoring it.
  #
  # @see https://developers.tesla.com/docs/fleet-api

  class Session
    attr_reader \
      :private_key,
      :vehicle_public_key,
      :session_key,
      :epoch,
      :counter,
      :clock_time,
      :routing_address

    # Creates a session from an established vehicle key exchange. When no
    # explicit clock offset is supplied, it derives the offset from the vehicle
    # clock and the local clock captured at initialization.
    #
    # @return [void] the operation result.

    def initialize(
      private_key:,
      vehicle_public_key:,
      session_key:,
      epoch:,
      counter:,
      clock_time:,
      routing_address:,
      local_time: Time.now.to_i,
      clock_offset: nil
    )
      @private_key = private_key
      @vehicle_public_key = vehicle_public_key
      @session_key = session_key
      @epoch = epoch
      @counter = counter
      @clock_time = clock_time
      @routing_address = routing_address

      @clock_offset =
        if clock_offset.nil?
          clock_time - local_time
        else
          clock_offset
        end
    end

    # Returns the next command counter currently held by the session without
    # changing it.
    #
    # @return [Integer] the requested protocol value.

    def current_counter
      @counter
    end

    # Advances the session counter by one and rejects exhaustion at the maximum
    # 32-bit unsigned value.
    #
    # @return [Integer] the command result or constructed protocol value.

    def advance_counter
      raise Tesla::ProtocolError,
            "session counter exhausted" if
        @counter >= 0xffff_ffff

      @counter += 1
    end

    # Converts a local Unix timestamp into the vehicle time domain using the
    # session clock offset.
    #
    # @param [Integer] local_time value used by the operation.
    # @return [Integer] the requested protocol value.

    def vehicle_time(local_time = Time.now.to_i)
      local_time + @clock_offset
    end

    # Returns the current vehicle-minus-local clock offset maintained by the
    # session.
    #
    # @return [Integer] the requested protocol value.

    def clock_offset
      @clock_offset
    end

    # Performs the `same epoch` operation used by the signed-command protocol
    # implementation.
    #
    # @return [Boolean] whether the requested condition is true.

    def same_epoch?(epoch)
      Crypto.secure_compare(
        @epoch,
        epoch
      )
    end

    # Updates the vehicle clock and recalculates the local clock offset. A
    # clock regression is rejected because it would invalidate protocol expiry
    # calculations.
    #
    # @return [Integer] the command result or constructed protocol value.

    def update_clock(
      clock_time,
      local_time: Time.now.to_i
    )
      if clock_time < @clock_time
        raise Tesla::ProtocolError,
              "vehicle clock regressed"
      end

      @clock_time = clock_time
      @clock_offset = clock_time - local_time
    end

    # Raises the stored counter when the authenticated vehicle reports a newer
    # value, while rejecting a counter regression.
    #
    # @param [Integer] counter value used by the operation.
    # @return [Integer] the command result or constructed protocol value.

    def update_counter(counter)
      if counter < @counter
        raise Tesla::ProtocolError,
              "session counter regressed"
      end

      @counter = counter
    end

    # Converts session state to the validated JSON-compatible representation
    # used by SessionCache. Binary keys are encoded as hexadecimal strings.
    #
    # @return [Hash{String => String, Integer}] the requested protocol value.

    def to_h
      {
        "session_key" =>
          @session_key.unpack1("H*"),

        "vehicle_public_key" =>
          Crypto.encoded_public_key(
            @vehicle_public_key
          ).unpack1("H*"),

        "epoch" =>
          @epoch.unpack1("H*"),

        "counter" =>
          @counter,

        "clock_time" =>
          @clock_time,

        "clock_offset" =>
          @clock_offset,

        "routing_address" =>
          @routing_address.unpack1("H*")
      }
    end

    # Restores a session from persisted hash data and verifies that the cached
    # session key is derivable from the supplied private key before accepting
    # the cache.
    #
    # @return [Tesla::Session] the command result or constructed protocol value.

    def self.from_h(
      data,
      private_key:
    )
      session_key =
        decode_hex_field(
          data,
          "session_key",
          16
        )

      vehicle_public_key_bytes =
        decode_hex_field(
          data,
          "vehicle_public_key",
          65
        )

      epoch =
        decode_hex_field(
          data,
          "epoch",
          16
        )

      routing_address =
        decode_hex_field(
          data,
          "routing_address",
          16
        )

      vehicle_public_key =
        Crypto.public_key_from_bytes(
          vehicle_public_key_bytes
        )

      expected_session_key =
        Crypto.session_key(
          private_key,
          vehicle_public_key
        )

      unless Crypto.secure_compare(
        expected_session_key,
        session_key
      )
        raise ArgumentError,
              "cached session key does not match private key"
      end

      new(
        private_key: private_key,
        vehicle_public_key: vehicle_public_key,
        session_key: session_key,
        epoch: epoch,
        counter: Integer(data.fetch("counter")),
        clock_time: Integer(data.fetch("clock_time")),
        clock_offset: Integer(data.fetch("clock_offset")),
        routing_address: routing_address
      )
    end

    private

    # Validates and decodes one fixed-size hexadecimal session field. Invalid,
    # malformed, or incorrectly sized values are rejected before cryptographic
    # use.
    #
    # @param [Hash{String => String, Integer}] data value used by the operation.
    # @param [String] key value used by the operation.
    # @param [Integer] expected_bytes value used by the operation.
    # @return [String] the requested protocol value.

    def self.decode_hex_field(data, key, expected_bytes)
      value = data.fetch(key)

      unless value.is_a?(String) &&
             value.length == expected_bytes * 2 &&
             value.match?(/\A[0-9a-fA-F]+\z/)
        raise ArgumentError,
              "invalid #{key}"
      end

      [value].pack("H*")
    end
  end
end
