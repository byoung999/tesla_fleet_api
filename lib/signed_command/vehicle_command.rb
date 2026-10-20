require "base64"
require "securerandom"

$LOAD_PATH.unshift(File.expand_path('.'         , __dir__))
$LOAD_PATH.unshift(File.expand_path('./protobuf', __dir__))

require "crypto"
require "metadata"
require "session"
require "session_cache"
require "safe_logger"
require "errors"
require "error_classifier"
require "fleet_transport"
require "protobuf_adapter"

module Tesla

  # Builds and sends authenticated VCSEC vehicle commands such as lock/unlock
  # and closure operations. It manages the VCSEC session handshake,
  # authenticated RoutableMessages, encrypted responses, and recovery from
  # recoverable session faults.
  #
  # @see https://developers.tesla.com/docs/fleet-api

  class VehicleCommand
    attr_reader :session

    #------------------------------------------------------------------------

    DOMAIN_VEHICLE_SECURITY = 2

    FLAG_ENCRYPT_RESPONSE = 2

    SIGNATURE_TYPE_HMAC              = 6
    SIGNATURE_TYPE_HMAC_PERSONALIZED = 8
    SIGNATURE_TYPE_AES_GCM_RESPONSE  = 9

    TAG_SIGNATURE_TYPE  = 0
    TAG_DOMAIN          = 1
    TAG_PERSONALIZATION = 2
    TAG_EPOCH           = 3
    TAG_EXPIRES_AT      = 4
    TAG_COUNTER         = 5
    TAG_CHALLENGE       = 6
    TAG_FLAGS           = 7
    TAG_REQUEST_HASH    = 8
    TAG_FAULT           = 9

    COMMAND_LIFETIME = 30

    RECOVERABLE_FAULTS = [
      :MESSAGEFAULT_ERROR_INVALID_SIGNATURE,
      :MESSAGEFAULT_ERROR_INVALID_TOKEN_OR_COUNTER,
      :MESSAGEFAULT_ERROR_INCORRECT_EPOCH,
      :MESSAGEFAULT_ERROR_TIME_EXPIRED
    ].freeze

    RKE_ACTION_LOCK         = :RKE_ACTION_LOCK
    RKE_ACTION_UNLOCK       = :RKE_ACTION_UNLOCK
    RKE_ACTION_REMOTE_DRIVE = :RKE_ACTION_REMOTE_DRIVE

    CLOSURE_MOVE_TYPE_NONE  = :CLOSURE_MOVE_TYPE_NONE
    CLOSURE_MOVE_TYPE_OPEN  = :CLOSURE_MOVE_TYPE_OPEN
    CLOSURE_MOVE_TYPE_CLOSE = :CLOSURE_MOVE_TYPE_CLOSE
    CLOSURE_MOVE_TYPE_MOVE  = :CLOSURE_MOVE_TYPE_MOVE
    CLOSURE_MOVE_TYPE_STOP  = :CLOSURE_MOVE_TYPE_STOP

    CLOSURE_VALUES = {
      'open':  :CLOSURE_MOVE_TYPE_OPEN,
      'close': :CLOSURE_MOVE_TYPE_CLOSE,
      'move':  :CLOSURE_MOVE_TYPE_MOVE,
      'stop':  :CLOSURE_MOVE_TYPE_STOP
    }

    ACTIONS = {
      lock:                 nil,
      unlock:               nil,
      remote_drive:         nil,
      front_driver_door:    CLOSURE_VALUES,
      front_passenger_door: CLOSURE_VALUES,
      rear_driver_door:     CLOSURE_VALUES,
      rear_passenger_door:  CLOSURE_VALUES,
      rear_trunk:           CLOSURE_VALUES,
      front_trunk:          CLOSURE_VALUES,
      charge_port:          CLOSURE_VALUES,
      tonneau:              CLOSURE_VALUES,
    }

    ALIASES = {}

    #------------------------------------------------------------------------

    # Class method to list supported commands.
    #
    # @return [Array<String>]] Array of supported commands

    def self.list_commands
      commands = []
      ACTIONS.each do |command, param|
        command  = command.to_s
        unless param.nil?
          command += ':'
          command += param.keys.join('|')
        end
        commands << command
      end

      commands
    end

    # Class method to check if the supplied command is valid.
    #
    # @param  command [String] Command to check
    # @return [Boolean] Whether command exists

    def self.valid_command?(command)
      matches = command.match(/\A(\w+)(:(.*)){0,1}\z/)
      return false if matches.nil?
      method = matches[1]
      method = ALIASES[method.to_sym] if ALIASES.key?(method.to_sym)
      ACTIONS.key?(method.to_sym)
    end

    # Class method to build a methods and arguments based on the specified
    # full command.
    #
    # @param  command [String] User supplied command
    # @return [Array] method [Symbol], kwargs [Hash]
    # @raise  [RuntimeError] Command not formatted correctly

    def self.build_call(command)
      matches = command.match(/\A(\w+)(:(.*)){0,1}\z/)

      raise "Invalid command format \"#{command}\"" if matches.nil?

      method = matches[1]
      method = ALIASES[method.to_sym] if ALIASES.key?(method.to_sym)
      param  = matches[3]

      raise "Invalid command name \"#{method}\"" unless ACTIONS.key?(method.to_sym)

      possible_values = ACTIONS[method.to_sym]

      if possible_values.nil?
        formatted_value = nil
        unless param.nil?
          raise "Invalid \"#{method}\" does not take a value"
        end
      else
        formatted_value = possible_values[param&.to_sym]
        if formatted_value.nil?
          raise "Invalid value for \"#{method}\" (#{param})"
        end
      end

      [method, formatted_value]
    end

    # Class method to call a car service command.
    #
    # @param  tesla_api [TeslaAPI]   TeslaAPI instance
    # @param  vin       [String]     VIN associated with request
    # @param  command   [String]     Command to run
    # @param  logger    [Logger,nil] Logger to use
    # @return [VCSEC::FromVCSECMessage, UniversalMessage::RoutableMessage, nil] Results of method called
    # @raise  [RuntimeError] If any problems encountered running command

    def self.command(tesla_api, vin, command, logger: nil)
      (method, params) = build_call(command)

      private_key_file = Config.find_config_file('private-key.pem')
      private_key      = OpenSSL::PKey::EC.new(File.read(private_key_file))
      transport        = Tesla::FleetTransport.new(tesla_api: tesla_api)
      protobuf         = Tesla::ProtobufAdapter.new

      vehicle_command =
        Tesla::VehicleCommand.new(
          vin:              vin,
          private_key:      private_key,
          transport:        transport,
          protobuf_adapter: protobuf,
          logger:           logger
        )

      if params.nil?
        vehicle_command.action(method)
      else
        vehicle_command.closure(method, params)
      end
    end

    #------------------------------------------------------------------------

    # Initializes a VCSEC executor with the application keypair, vehicle
    # identity, Fleet transport, protobuf adapter, optional persistent session
    # cache, and sanitized logger.
    #
    # @return [void] the operation result.

    def initialize(
      vin:,
      private_key:,
      transport:,
      protobuf_adapter:,
      session_cache: nil,
      logger: nil
    )
      @vin             = vin
      @private_key     = private_key
      @transport       = transport
      @protobuf        = protobuf_adapter
      @session_cache   = session_cache
      @logger          = logger || Tesla::SafeLogger.new

      @session         = nil
      @routing_address = nil
      @command_mutex   = Mutex.new
    end

    #------------------------------------------------------------------------


    # Builds and sends a VCSEC authenticated RoutableMessage, verifies/decrypts
    # the response, and retries once after synchronizing session state when the
    # vehicle reports a recoverable session fault.
    #
    # @param [VCSEC::UnsignedMessage] unsigned_message value used by the operation.
    # @param [Boolean] retry_on_sync_error value used by the operation.
    # @return [VCSEC::FromVCSECMessage, UniversalMessage::RoutableMessage, nil] the command result or constructed protocol value.

    def send_authenticated_command(unsigned_message, retry_on_sync_error: true)
      command_bytes = @protobuf.encode_unsigned_message(unsigned_message)

      if @session_cache
        @session =
          @session_cache.reserve_counter(
            private_key: @private_key,
            session:     @session
          )

        @routing_address = @session.routing_address
      else
        @session.advance_counter
      end

      request = build_authenticated_routable(command_bytes)

      response =
        @transport.signed_command(
          vin: @vin,
          routable_message:
            Base64.strict_encode64(
              @protobuf.encode_routable(request.fetch(:routable))
            )
        )

      unless response.is_a?(Hash)
        raise Tesla::ProtocolError, "signed command response is missing"
      end

      encoded_response = response[:response] || response["response"]

      unless encoded_response.is_a?(String) && !encoded_response.empty?
        raise Tesla::ProtocolError,
              "signed command response is missing response field"
      end

      response_bytes =
        begin
          Base64.strict_decode64(encoded_response)
        rescue ArgumentError
          raise Tesla::ProtocolError,
                "signed command response contains invalid base64"
        end

      response_message = @protobuf.decode_routable(response_bytes)
      fault            = @protobuf.signed_message_fault(response_message)

      if fault && fault != :MESSAGEFAULT_ERROR_NONE
        recovered =
          recover_from_session_info(
            response_message,
            request_uuid: request.fetch(:request_uuid),
            fault:        fault
          )

        if retry_on_sync_error && RECOVERABLE_FAULTS.include?(fault)
          unless recovered
            @session         = nil
            @routing_address = nil

            @session_cache.delete if @session_cache
          end

          ensure_session

          return send_authenticated_command(
            unsigned_message,
            retry_on_sync_error: false
          )
        end

        raise Tesla::ProtocolError.new(
          "vehicle returned protocol fault #{fault}"
        )
      end

      decrypt_response(
        response_message,
        request_hash: request.fetch(:request_hash)
      )
    end

    # Resolves a named VCSEC action to the protobuf enum/value expected by the
    # RKE action builder.
    #
    # @param [String] action_name value used by the operation.
    # @return [VCSEC::FromVCSECMessage, UniversalMessage::RoutableMessage, nil] the command result or constructed protocol value.

    def action(action_name)
      var_name = "Tesla::VehicleCommand::RKE_ACTION_#{action_name.upcase}"
      begin
        rke_action = Object.const_get(var_name)
      rescue NameError
        raise "Invalid action name \"#{action_name}\"", cause: nil
      end
      send_rke_action(rke_action)
    end

    # Resolves a closure name and move type into the VCSEC closure protobuf
    # values used by closure commands.
    #
    # @param [String] closure_name value used by the operation.
    # @param [String] move_type_name value used by the operation.
    # @return [VCSEC::FromVCSECMessage, UniversalMessage::RoutableMessage, nil] the command result or constructed protocol value.

    def closure(closure_name, move_type_name)
      # Handle move_type_name being a string or a label that may or may not
      # include CLOSURE_MOVE_TYPE_ at the beginning.
      short_move_type = move_type_name.to_s.sub(/CLOSURE_MOVE_TYPE_/, '').upcase
      var_name = "Tesla::VehicleCommand::CLOSURE_MOVE_TYPE_#{short_move_type}"
      begin
        move_type = Object.const_get(var_name)
      rescue NameError
        raise "Invalid movement type \"#{move_type_name}\"", cause: nil
      end
      send_closure_move(closure_name.to_sym => move_type)
    end

    # Sends the VCSEC remote-key lock action to the vehicle and returns the
    # decoded command result.
    #
    # @return [VCSEC::FromVCSECMessage, UniversalMessage::RoutableMessage, nil] the command result or constructed protocol value.

    def door_lock
      send_rke_action(RKE_ACTION_LOCK)
    end

    # Sends the VCSEC remote-key unlock action to the vehicle and returns the
    # decoded command result.
    #
    # @return [VCSEC::FromVCSECMessage, UniversalMessage::RoutableMessage, nil] the command result or constructed protocol value.

    def door_unlock
      send_rke_action(RKE_ACTION_UNLOCK)
    end

    # Sends the VCSEC remote-drive action requested by the caller.
    #
    # @return [VCSEC::FromVCSECMessage, UniversalMessage::RoutableMessage, nil] the command result or constructed protocol value.

    def remote_drive
      send_rke_action(RKE_ACTION_REMOTE_DRIVE)
    end

    # Sends the VCSEC command that opens the trunk closure.
    #
    # @return [VCSEC::FromVCSECMessage, UniversalMessage::RoutableMessage, nil] the command result or constructed protocol value.

    def open_trunk
      send_closure_move(
        rear_trunk: :CLOSURE_MOVE_TYPE_OPEN
      )
    end

    # Sends the VCSEC command that closes the trunk closure.
    #
    # @return [VCSEC::FromVCSECMessage, UniversalMessage::RoutableMessage, nil] the command result or constructed protocol value.

    def close_trunk
      send_closure_move(
        rear_trunk: :CLOSURE_MOVE_TYPE_CLOSE
      )
    end

    # Sends the VCSEC command that opens the front-trunk closure.
    #
    # @return [VCSEC::FromVCSECMessage, UniversalMessage::RoutableMessage, nil] the command result or constructed protocol value.

    def open_frunk
      send_closure_move(
        front_trunk: :CLOSURE_MOVE_TYPE_OPEN
      )
    end

    # Sends the VCSEC command that closes the front-trunk closure.
    #
    # @return [VCSEC::FromVCSECMessage, UniversalMessage::RoutableMessage, nil] the command result or constructed protocol value.

    def close_frunk
      send_closure_move(
        front_trunk: :CLOSURE_MOVE_TYPE_CLOSE
      )
    end

    # Sends the VCSEC command that opens the charge-port door.
    #
    # @return [VCSEC::FromVCSECMessage, UniversalMessage::RoutableMessage, nil] the command result or constructed protocol value.

    def open_charge_port
      send_closure_move(
        charge_port: :CLOSURE_MOVE_TYPE_OPEN
      )
    end

    # Sends the VCSEC command that closes the charge-port door.
    #
    # @return [VCSEC::FromVCSECMessage, UniversalMessage::RoutableMessage, nil] the command result or constructed protocol value.

    def close_charge_port
      send_closure_move(
        charge_port: :CLOSURE_MOVE_TYPE_CLOSE
      )
    end

    # Builds an RKEAction protobuf for the requested action and sends it
    # through the authenticated VCSEC command path.
    #
    # @param [Symbol] action value used by the operation.
    # @return [VCSEC::FromVCSECMessage, UniversalMessage::RoutableMessage, nil] the command result or constructed protocol value.

    def send_rke_action(action)
      @command_mutex.synchronize do
        @logger.info(
          "command_start",
          action: action
        )

        begin
          ensure_session

          unsigned_message =
            @protobuf.build_rke_action(
              action
            )

          result =
            send_authenticated_command(
              unsigned_message
            )

          @logger.info(
            "command_complete",
            action: action,
            counter: @session.current_counter
          )

          result
        rescue StandardError => error
          @logger.error(
            "command_failed",
            action:   action,
            category: Tesla::ErrorClassifier.classify(error),
            error:    error
          )

          raise
        end
      end
    end

    # Builds one or more closure move operations and sends them as an
    # authenticated VCSEC command.
    #
    # @param [Hash{Symbol => Symbol}] closures value used by the operation.
    # @return [VCSEC::FromVCSECMessage, UniversalMessage::RoutableMessage, nil] the command result or constructed protocol value.

    def send_closure_move(**closures)
      @command_mutex.synchronize do
        @logger.info(
          "command_start",
          action: :CLOSURE_MOVE,
          closures: closures
        )

        begin
          ensure_session

          unsigned_message =
            @protobuf.build_closure_move(
              **closures
            )

          result =
            send_authenticated_command(
              unsigned_message
            )

          @logger.info(
            "command_complete",
            action: :CLOSURE_MOVE,
            closures: closures,
            counter: @session.current_counter
          )

          result
        rescue StandardError => error
          @logger.error(
            "command_failed",
            action: :CLOSURE_MOVE,
            closures: closures,
            category:
              Tesla::ErrorClassifier.classify(error),
            error: error
          )

          raise
        end
      end
    end

    # Performs the VCSEC session handshake, derives the session key from the
    # vehicle public key, validates the returned SessionInfo authentication
    # data, and installs the resulting session state.
    #
    # @return [Tesla::Session] the command result or constructed protocol value.

    def establish_session
      @logger.info("session_establishing")

      local_time      = Time.now.to_i
      routing_address = SecureRandom.random_bytes(16)
      request_uuid    = SecureRandom.random_bytes(16)

      request = @protobuf.build_session_info_request(
        domain:          DOMAIN_VEHICLE_SECURITY,
        routing_address: routing_address,
        public_key:      Crypto.encoded_public_key(@private_key),
        uuid:            request_uuid
      )

      response = @transport.signed_command(
        vin: @vin,
        routable_message:
          Base64.strict_encode64(@protobuf.encode_routable(request))
      )

      unless response.is_a?(Hash)
        raise Tesla::ProtocolError, "signed command response is missing"
      end

      encoded_response = response[:response] || response["response"]

      unless encoded_response.is_a?(String) && !encoded_response.empty?
        raise Tesla::ProtocolError,
              "signed command response is missing response field"
      end

      response_bytes =
        begin
          Base64.strict_decode64(encoded_response)
        rescue ArgumentError
          raise Tesla::ProtocolError,
                "signed command response contains invalid base64"
        end

      response_message = @protobuf.decode_routable(response_bytes)
      actual_tag       = @protobuf.session_info_tag(response_message)

      unless actual_tag
        raise Tesla::ProtocolError,
              "session establishment response is missing authentication tag"
      end

      session_info_bytes = @protobuf.session_info_bytes(response_message)

      unless session_info_bytes
        raise Tesla::ProtocolError,
              "session establishment response is missing session info"
      end

      session_info = @protobuf.decode_session_info(session_info_bytes)

      vehicle_public_key = Crypto.public_key_from_bytes(
        @protobuf.session_public_key(session_info)
      )

      session_key = Crypto.session_key(@private_key, vehicle_public_key)

      expected_tag = session_info_tag(
        session_info_bytes: session_info_bytes,
        session_key:        session_key,
        challenge:          request_uuid
      )

      unless Crypto.secure_compare(expected_tag, actual_tag)
        raise Tesla::AuthenticationError,
              "invalid session info authentication tag"
      end

      @routing_address = routing_address

      @session =
        Session.new(
          private_key:        @private_key,
          vehicle_public_key: vehicle_public_key,
          session_key:        session_key,
          epoch:              @protobuf.session_epoch(session_info),
          counter:            @protobuf.session_counter(session_info),
          clock_time:         @protobuf.session_clock_time(session_info),
          routing_address:    routing_address,
          local_time:         local_time
        )

        @logger.info(
          "session_established",
          counter: @session.current_counter
        )

      @session_cache.save(@session) if @session_cache

      @session
    end

    #------------------------------------------------------------------------

    private

    #------------------------------------------------------------------------

    # Reuses the current session when available; otherwise loads a compatible
    # cached session or performs a fresh VCSEC handshake.
    #
    # @return [Tesla::Session] the command result or constructed protocol value.

    def ensure_session
      return @session if @session

      if @session_cache
        data = @session_cache.load

        if data
          begin
            @session = Tesla::Session.from_h(data, private_key: @private_key)

            @routing_address = @session.routing_address

            @logger.info(
              "session_restored",
              counter: @session.current_counter
            )

            return @session
          rescue StandardError => error
            @logger.warn("session_restore_failed", error: error)
            @session_cache.delete
          end
        end
      end

      establish_session
    end

    # Computes the expected SessionInfo authentication tag from the session key
    # and handshake challenge.
    #
    # @param [String] session_info_bytes value used by the operation.
    # @param [String] session_key value used by the operation.
    # @param [String] challenge value used by the operation.
    # @return [String] the command result or constructed protocol value.

    def session_info_tag(session_info_bytes:, session_key:, challenge:)
      metadata = Metadata.new
        .put_byte(TAG_SIGNATURE_TYPE, SIGNATURE_TYPE_HMAC)
        .put(TAG_PERSONALIZATION, @vin     )
        .put(TAG_CHALLENGE      , challenge)

      Crypto.hmac_sha256(
        Crypto.session_info_key(session_key),
        metadata.serialize + session_info_bytes
      )
    end

    # Returns the digest value that binds an authenticated response to the
    # original request.
    #
    # @param [String] tag value used by the operation.
    # @return [String] the requested protocol value.

    def request_hash(tag)
      [SIGNATURE_TYPE_HMAC_PERSONALIZED].pack("C") + tag.byteslice(0, 16)
    end

    # Constructs the VCSEC authenticated RoutableMessage, including metadata
    # needed to bind the command to the current session and request.
    #
    # @param [String] command_bytes value used by the operation.
    # @return [Hash{Symbol => Object}] the command result or constructed protocol value.

    def build_authenticated_routable(command_bytes)
      vehicle_time = @session.vehicle_time
      expires_at   = vehicle_time + COMMAND_LIFETIME
      counter      = @session.current_counter

      metadata = Metadata.new
        .put_byte(TAG_SIGNATURE_TYPE, SIGNATURE_TYPE_HMAC_PERSONALIZED)
        .put_byte(TAG_DOMAIN        , DOMAIN_VEHICLE_SECURITY         )
        .put(TAG_PERSONALIZATION, @vin                 )
        .put(TAG_EPOCH          , @session.epoch       )
        .put(TAG_EXPIRES_AT     , expires_at           )
        .put(TAG_COUNTER        , counter              )
        .put(TAG_FLAGS          , FLAG_ENCRYPT_RESPONSE)

      metadata_bytes = metadata.serialize
      command_key    = Crypto.command_key(@session.session_key)
      tag  = Crypto.hmac_sha256(command_key, metadata_bytes + command_bytes)
      uuid = SecureRandom.random_bytes(16)

      routable =
        @protobuf.build_hmac_routable(
          domain:                    DOMAIN_VEHICLE_SECURITY,
          routing_address:           @session.routing_address,
          uuid:                      uuid,
          protobuf_message_as_bytes: command_bytes,
          metadata:                  metadata,
          metadata_bytes:            metadata_bytes,
          tag:                       tag,
          public_key:                Crypto.encoded_public_key(@private_key),
          flags:                     FLAG_ENCRYPT_RESPONSE
        )

      {
        routable:     routable,
        request_hash: request_hash(tag),
        request_uuid: uuid
      }
    end

    # Checks response/request binding and duplicate counters before AES-GCM
    # decryption, then decodes the authenticated plaintext into the VCSEC response structure.
    #
    # @param [UniversalMessage::RoutableMessage] message value used by the operation.
    # @param [String] request_hash value used by the operation.
    # @return [VCSEC::FromVCSECMessage, UniversalMessage::RoutableMessage, nil] the command result or constructed protocol value.

    def decrypt_response(message, request_hash:)
      ensure_session

      unless @protobuf.response_is_encrypted?(message)
        return message
      end

      response_counter = @protobuf.response_counter(message)
      expected_counter = @session.current_counter

      unless response_counter == expected_counter
        raise Tesla::ProtocolError, "invalid response counter"
      end

      ciphertext = @protobuf.response_ciphertext(message)
      tag        = @protobuf.response_tag(message)
      iv         = @protobuf.response_iv(message)
      fault      = @protobuf.signed_message_fault(message)

      fault =
        if fault.nil?
          0
        elsif fault.is_a?(Symbol)
          UniversalMessage::MessageFault_E.resolve(fault)
        else
          fault
        end

      flags = @protobuf.response_flags(message)

      response_metadata = Metadata.new
        .put_byte(TAG_SIGNATURE_TYPE , SIGNATURE_TYPE_AES_GCM_RESPONSE)
        .put_byte(TAG_DOMAIN         , DOMAIN_VEHICLE_SECURITY        )
        .put(TAG_PERSONALIZATION, @vin            )
        .put(TAG_COUNTER        , response_counter)
        .put(TAG_FLAGS          , flags           )
        .put(TAG_REQUEST_HASH   , request_hash    )
        .put(TAG_FAULT          , fault           )

      aad = Crypto.sha256(response_metadata.serialize)

      plaintext =
        Crypto.aes_gcm_decrypt(
          key:        @session.session_key,
          iv:         iv,
          ciphertext: ciphertext,
          tag:        tag,
          aad:        aad
        )

      return nil if plaintext.empty?

      @protobuf.decode_command_response(plaintext)
    end

    # Uses authenticated SessionInfo attached to a recoverable error response
    # to repair stale local session state before the original command is retried.
    #
    # @param [UniversalMessage::RoutableMessage] message value used by the operation.
    # @param [String] request_uuid value used by the operation.
    # @param [Symbol, Integer] fault value used by the operation.
    # @return [Boolean] the command result or constructed protocol value.

    def recover_from_session_info(message, request_uuid:, fault:)
      return false unless RECOVERABLE_FAULTS.include?(fault)

      session_info_bytes = @protobuf.response_session_info(message)

      return false unless session_info_bytes

      response_uuid = @protobuf.response_request_uuid(message)

      unless response_uuid.nil? || response_uuid.empty?
        return false unless Crypto.secure_compare(response_uuid, request_uuid)
      end

      actual_tag = @protobuf.session_info_tag(message)

      return false unless actual_tag

      session_info = @protobuf.decode_session_info(session_info_bytes)

      vehicle_public_key =
        Crypto.public_key_from_bytes(
          @protobuf.session_public_key(
            session_info
          )
        )

      session_key = Crypto.session_key(@private_key, vehicle_public_key)

      expected_tag =
        session_info_tag(
          session_info_bytes: session_info_bytes,
          session_key:        session_key,
          challenge:          request_uuid
        )

      unless Crypto.secure_compare(expected_tag, actual_tag)
        @session         = nil
        @routing_address = nil

        raise Tesla::AuthenticationError,
              "invalid piggy-backed session info authentication tag"
      end

      update_session_from_authenticated_info(
        session_info:       session_info,
        vehicle_public_key: vehicle_public_key,
        session_key:        session_key
      )

      true
    rescue ArgumentError, OpenSSL::PKey::PKeyError
      false
    end

    # Installs authenticated vehicle session state while preserving the current
    # epoch/counter/clock invariants and persisting the new state when a SessionCache is configured.
    #
    # @return [TrueClass, nil] the command result or constructed protocol value.

    def update_session_from_authenticated_info(
      session_info:,
      vehicle_public_key:,
      session_key:
    )
      new_epoch      = @protobuf.session_epoch(session_info)
      new_counter    = @protobuf.session_counter(session_info)
      new_clock_time = @protobuf.session_clock_time(session_info)
      old_session    = @session

      if old_session.same_epoch?(new_epoch)
        if new_clock_time < old_session.clock_time
          raise Tesla::ProtocolError,
                "vehicle returned regressed session clock"
        end

        new_counter = [ new_counter, old_session.current_counter ].max
      end

      @session =
        Session.new(
          private_key:        @private_key,
          vehicle_public_key: vehicle_public_key,
          session_key:        session_key,
          epoch:              new_epoch,
          counter:            new_counter,
          clock_time:         new_clock_time,
          routing_address:    old_session.routing_address,
          local_time:         Time.now.to_i
        )

      @routing_address = @session.routing_address

      @session_cache.save(@session) if @session_cache
    end

    # Releases command-local resources and clears the active session reference
    # when the executor is no longer needed.
    #
    # @return [void] the command result or constructed protocol value.

    def close
      @command_mutex.synchronize do
        @session         = nil
        @routing_address = nil
      end

      true
    end

    #------------------------------------------------------------------------

  end

end
