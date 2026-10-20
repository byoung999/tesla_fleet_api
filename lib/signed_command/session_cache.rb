require "json"
require "fileutils"
require "tempfile"

module Tesla

  # Persistent, file-backed store for signed-command session state. It uses an
  # exclusive lock and atomic replacement so multiple processes can reserve
  # monotonically increasing counters without corrupting the cached session.
  #
  # @see https://developers.tesla.com/docs/fleet-api

  class SessionCache
    FILE_MODE = 0o600
    LOCK_MODE = 0o600

    # Creates a session cache backed by the supplied JSON path and derives the
    # companion lock-file path.
    #
    # @param [String] path value used by the operation.
    # @return [void] the operation result.

    def initialize(path)
      @path = path
      @lock_path = "#{path}.lock"
    end

    # Loads and validates the cached session while holding the cache lock.
    # Invalid persisted data is discarded and reported as no cached session.
    #
    # @return [Hash, nil] the requested protocol value.

    def load
      with_lock do
        load_unlocked
      end
    end

    # Reads and validates the cache without acquiring the lock. This is used
    # internally when a caller already owns the cache lock.
    #
    # @return [Hash, nil] the command result or constructed protocol value.

    def load_unlocked
      return nil unless File.file?(@path)

      begin
        data =
          JSON.parse(
            File.read(@path)
          )

        validate!(data)

        data
      rescue JSON::ParserError,
             KeyError,
             TypeError,
             ArgumentError
        delete_unlocked
        nil
      end
    end

    # Validates and atomically persists the session while holding the cache
    # lock. The method returns true after the durable replacement succeeds.
    #
    # @param [Tesla::Session] session value used by the operation.
    # @return [TrueClass] the operation result.

    def save(session)
      data =
        session.to_h

      validate!(
        data
      )

      with_lock do
        save_unlocked(
          data
        )
      end

      true
    end

    # Writes validated session data to a temporary file, fsyncs it, and
    # atomically renames it over the cache file. The temporary file is removed
    # if the operation fails.
    #
    # @param [Hash] data value used by the operation.
    # @return [void] the operation result.

    def save_unlocked(data)
      directory =
        File.dirname(@path)

      FileUtils.mkdir_p(
        directory
      )

      temp_path = nil

      begin
        Tempfile.create(
          [".session-", ".tmp"],
          directory
        ) do |file|
          temp_path = file.path

          File.chmod(
            FILE_MODE,
            temp_path
          )

          file.write(
            JSON.generate(data)
          )

          file.flush
          file.fsync

          File.rename(
            temp_path,
            @path
          )

          temp_path = nil
        end
      ensure
        if temp_path &&
           File.exist?(temp_path)
          File.unlink(
            temp_path
          )
        end
      end

      File.chmod(
        FILE_MODE,
        @path
      )
    end

    # Atomically reconciles the in-memory session with the persisted session
    # and reserves the next command counter. A newer cached session replaces
    # the caller's session; epoch and routing-address changes are rejected.
    #
    # @return [Tesla::Session] the command result or constructed protocol value.

    def reserve_counter(
      private_key:,
      session:
    )
      with_lock do
        data =
          load_unlocked

        unless data
          raise Tesla::ProtocolError,
                "session cache is empty"
        end

        cached_session =
          Tesla::Session.from_h(
            data,
            private_key: private_key
          )

        unless Crypto.secure_compare(
          cached_session.epoch,
          session.epoch
        )
          raise Tesla::ProtocolError,
                "cached session epoch changed"
        end

        unless Crypto.secure_compare(
          cached_session.routing_address,
          session.routing_address
        )
          raise Tesla::ProtocolError,
                "cached session routing address changed"
        end

        if cached_session.current_counter >
           session.current_counter
          session =
            cached_session
        end

        session.advance_counter

        save_unlocked(
          session.to_h
        )

        session
      end
    end

    # Deletes the persisted session while holding the cache lock. Missing cache
    # files are treated as a no-op.
    #
    # @return [TrueClass, nil] the operation result.

    def delete
      with_lock do
        delete_unlocked
      end
    end

    private

    # Executes a block while holding an exclusive advisory lock on the cache
    # lock file, releasing the lock even when the block raises.
    #
    # @return [Object] the operation result.

    def with_lock
      directory = File.dirname(@lock_path)
      FileUtils.mkdir_p(directory)

      File.open(
        @lock_path,
        File::RDWR | File::CREAT,
        LOCK_MODE
      ) do |lock|
        lock.flock(File::LOCK_EX)

        begin
          yield
        ensure
          lock.flock(File::LOCK_UN)
        end
      end
    end

    # Removes the cache file without acquiring the lock. Callers must already
    # hold the cache lock.
    #
    # @return [TrueClass, nil] the operation result.

    def delete_unlocked
      return nil unless File.exist?(@path)

      File.unlink(@path)

      true
    end

    # Performs the `validate` operation used by the signed-command protocol
    # implementation.
    #
    # @return [Hash] the command result or constructed protocol value.

    def validate!(data)
      required = %w[
        session_key
        vehicle_public_key
        epoch
        counter
        clock_time
        clock_offset
        routing_address
      ]

      required.each do |key|
        raise KeyError, key unless data.key?(key)
      end

      validate_hex!(
        data.fetch("session_key"),
        16,
        "session_key"
      )

      validate_hex!(
        data.fetch("vehicle_public_key"),
        65,
        "vehicle_public_key"
      )

      validate_hex!(
        data.fetch("epoch"),
        16,
        "epoch"
      )

      validate_hex!(
        data.fetch("routing_address"),
        16,
        "routing_address"
      )

      counter =
        Integer(data.fetch("counter"))

      unless counter.between?(0, 0xffff_ffff)
        raise ArgumentError,
              "invalid session counter"
      end

      Integer(data.fetch("clock_time"))
      Integer(data.fetch("clock_offset"))

      data
    end

    # Performs the `validate hex` operation used by the signed-command protocol
    # implementation.
    #
    # @return [void] the command result or constructed protocol value.

    def validate_hex!(value, expected_bytes, name)
      unless value.is_a?(String) &&
             value.match?(/\A[0-9a-fA-F]+\z/) &&
             value.length == expected_bytes * 2
        raise ArgumentError,
              "invalid #{name}"
      end
    end

  end
end
