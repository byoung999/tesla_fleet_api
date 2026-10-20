require "minitest/autorun"
require "openssl"
require "base64"

require "test_helper"
require "vehicle_command"
require "session"
require "crypto"

class FakeProtobufAdapter
  attr_reader :calls
  attr_reader :request_uuid

  def initialize(
    encrypted_response: false,
    response_counter: 0,
    ciphertext: "CIPHERTEXT",
    tag: "\x22".b * 16,
    nonce: "\x33".b * 12,
    plaintext: "PLAINTEXT",
    flags: 0,
    session_info: nil,
    request_uuid: nil,
    session_info_tag: nil,
    fault: :MESSAGEFAULT_ERROR_NONE
  )
    @encrypted_response = encrypted_response
    @response_counter = response_counter
    @ciphertext = ciphertext
    @tag = tag
    @nonce = nonce
    @plaintext = plaintext
    @calls = []
    @flags = flags
    @session_info = session_info
    @request_uuid = request_uuid
    @session_info_tag = session_info_tag
    @fault = fault
  end

  def response_is_encrypted?(message)
    @calls << [:encrypted_response?, message]
    @encrypted_response
  end

  def response_counter(message)
    @calls << [:response_counter, message]
    @response_counter
  end

  def response_ciphertext(message)
    @calls << [:response_ciphertext, message]
    @ciphertext
  end

  def response_tag(message)
    @calls << [:response_tag, message]
    @tag
  end

  def response_iv(message)
    @calls << [:response_iv, message]
    @nonce
  end

  def response_flags(message)
    @calls << [:response_flags, message]
    @flags
  end

  def response_session_info(message)
    @calls << [:response_session_info, message]
    @session_info
  end

  def response_request_uuid(message)
    @calls << [:response_request_uuid, message]
    @request_uuid
  end

  def session_info_bytes(info)
    @calls << [:session_info_bytes, info]
    @session_info
  end

  def session_info_tag(message)
    @calls << [:session_info_tag, message]
    @session_info_tag
  end

  def decode_encrypted_response(bytes)
    @calls << [:decode_encrypted_response, bytes]
    @plaintext
  end

  def build_rke_action(action)
    @calls << [:build_rke_action, action]
    action
  end

  def encode_unsigned_message(message)
    @calls << [:encode_unsigned_message, message]
    message.to_s
  end

  def build_hmac_routable(**kwargs)
    @calls << [:build_hmac_routable, kwargs]
    :routable
  end

  def encode_routable(message)
    @calls << [:encode_routable, message]
    "ENCODED_ROUTABLE"
  end

  def decode_routable(bytes)
    @calls << [:decode_routable, bytes]
    :response_message
  end

  def signed_message_fault(message)
    @calls << [:signed_message_fault, message]
    @fault
  end

  def decode_command_response(message)
    @calls << [:decode_command_response, message]
    :command_result
  end

  def build_session_info_request(**args)
    @calls << [:build_session_info_request, args]
    raise Tesla::ProtocolError,
          "fresh session establishment attempted"
  end

  def decode_session_info(_message)
    @calls << [:decode_session_info, _message]
    @session_info
  end

end


class FakeTransport
  attr_reader :calls

  def initialize(response)
    @response = response
    @calls = []
  end

  def signed_command(**kwargs)
    @calls << [:signed_command, kwargs]
    @response
  end
end


class TestVehicleCommand < Minitest::Test

  VIN = "5YJTESTVIN1234567"

  def setup
    @private_key =
      OpenSSL::PKey::EC.generate("prime256v1")

    setup_command
  end

  def setup_command(
    vin:           VIN,
    private_key:   @private_key,
    protobuf:      FakeProtobufAdapter.new,
    transport:     FakeTransport.new( response: "RESPONSE"),
    session:       nil,
    session_cache: nil,
    logger:        SilentLogger.new
  )
    @private_key   = private_key
    @protobuf      = protobuf
    @transport     = transport
    @logger        = logger
    @session_cache = session_cache

    vin = VIN if vin.nil?

    @command =
      Tesla::VehicleCommand.new(
        vin:              vin,
        private_key:      @private_key,
        transport:        @transport,
        protobuf_adapter: @protobuf,
        session_cache:    @session_cache,
        logger:           @logger
      )

    @session = session.nil? ? build_session : session
    @command.instance_variable_set(:@session, @session)
  end

  def test_door_lock_builds_lock_command
    result = @command.door_lock

    assert_equal(
      :response_message,
      result
    )

    assert_includes(
      @protobuf.calls,
      [:build_rke_action, :RKE_ACTION_LOCK]
    )

    assert_includes(
      @protobuf.calls,
      [:encode_unsigned_message, :RKE_ACTION_LOCK]
    )

    assert_includes(
      @transport.calls,
      [
        :signed_command,
        {
          vin: VIN,
          routable_message:
            Base64.strict_encode64("ENCODED_ROUTABLE")
        }
      ]
    )
  end

  def test_door_unlock_builds_unlock_command
    result = @command.door_unlock

    assert_equal(
      :response_message,
      result
    )

    assert_includes(
      @protobuf.calls,
      [:build_rke_action, :RKE_ACTION_UNLOCK]
    )

    assert_includes(
      @protobuf.calls,
      [:encode_unsigned_message, :RKE_ACTION_UNLOCK]
    )
  end

  def test_command_increments_session_counter
    initial_counter =
      @command.session.current_counter

    @command.door_lock

    assert_equal(
      initial_counter + 1,
      @command.session.current_counter
    )
  end

  def test_rejects_response_with_wrong_counter
    setup_command(
      protobuf: FakeProtobufAdapter.new(
        encrypted_response: true,
        response_counter: 999
      )
    )

    @protobuf.define_singleton_method(
      :response_counter
    ) do |_message|
      999
    end

    assert_raises(Tesla::ProtocolError) do
      @command.door_lock
    end
  end

  def test_empty_encrypted_response_is_success
    @protobuf.instance_variable_set(:@encrypted_response, true)

    @protobuf.instance_variable_set(
      :@response_counter,
      @session.current_counter
    )

    @protobuf.instance_variable_set(
      :@ciphertext,
      ""
    )

    @protobuf.instance_variable_set(
      :@tag,
      valid_gcm_tag
    )

    @protobuf.instance_variable_set(
      :@nonce,
      "3".b * 12
    )

    Tesla::Crypto.stub(:aes_gcm_decrypt, "") do
      result =
        @command.send(
          :decrypt_response,
          "",
          request_hash: "\x08".b + ("\xAA".b * 16)
        )

      assert_nil result
    end
  end

  def test_encrypted_response_is_decrypted
    setup_command(
      protobuf: FakeProtobufAdapter.new(
        encrypted_response: true,
        response_counter: 11
      ),
      transport: FakeTransport.new(
        response: Base64.strict_encode64("ENCRYPTED_RESPONSE")
      )
    )

    unsigned_message =
      @protobuf.build_rke_action(
        :RKE_ACTION_LOCK
      )

    Tesla::Crypto.stub(
      :aes_gcm_decrypt,
      lambda do |key:, iv:, ciphertext:, tag:, aad:|
        assert_equal @command.session.session_key, key
        assert_equal "\x33".b * 12               , iv
        assert_equal "CIPHERTEXT"                , ciphertext
        assert_equal "\x22".b * 16               , tag
        refute_empty aad

        "DECRYPTED_BYTES"
      end
    ) do
      result =
        @command.send_authenticated_command(
          unsigned_message
        )

      assert_equal :command_result, result
    end

    assert_includes(
      @protobuf.calls,
      [:decode_command_response, "DECRYPTED_BYTES"]
    )
  end

  def test_authenticated_command_uses_16_byte_request_uuid
    setup_command(
      protobuf: FakeProtobufAdapter.new(
        request_uuid: "\x44".b * 16
      ),
    )

    @command.door_lock

    uuid =
      @protobuf.request_uuid

    refute_nil(
      uuid
    )

    assert_equal(
      16,
      uuid.bytesize
    )
  end

  def test_command_failure_is_logged_and_reraised
    transport =
      Object.new

    def transport.signed_command(**)
      raise Tesla::RetryableError,
            "connection failed"
    end

    setup_command(
      transport: transport,
      logger: RecordingLogger.new
    )

    assert_raises(
      Tesla::RetryableError
    ) do
      @command.door_lock
    end

    failure =
      @logger.events.find do |level, event, _fields|
        level == :error &&
          event == "command_failed"
      end

    refute_nil(
      failure
    )

    fields =
      failure.fetch(2)

    assert_equal(
      :transport,
      fields.fetch(:category)
    )
  end

  def test_request_hash_is_17_bytes
    tag = "\xAA".b * 32

    setup_command()

    request_hash = @command.send(
      :request_hash,
      tag
    )

    assert_equal 17, request_hash.bytesize

    assert_equal(
      [8].pack("C") + ("\xAA".b * 16),
      request_hash
    )
  end

  def test_uses_cached_session_without_handshake
    session =
      build_session

    events = []

    session_cache = Class.new do
      def initialize(session, events)
        @session = session
        @events = events
      end

      def load
        @events << :load

        @session.to_h
      end

      def reserve_counter(
        private_key:,
        session:
      )
        @events << :reserve_counter

        @session.advance_counter

        @session
      end
    end.new(
      session,
      events
    )

    transport = Class.new do
      def initialize(events)
        @events = events
      end

      def signed_command(**kwargs)
        @events << :transport
        { response: Base64.strict_encode64("RESPONSE") }
      end
    end.new(events)

    setup_command(
      transport: transport,
      session_cache: session_cache
    )

    @command.instance_variable_set(
      :@session,
      nil
    )

    @command.door_lock

    assert_equal(
      [
        :load,
        :reserve_counter,
        :transport
      ],
      events
    )
  end

  def test_valid_piggybacked_session_info_updates_session
    old_session =
      build_session

    new_vehicle_key =
      Tesla::Crypto.generate_key

    new_vehicle_public_key =
      Tesla::Crypto.public_key_from_bytes(
        Tesla::Crypto.encoded_public_key(
          new_vehicle_key
        )
      )

    new_session_key =
      Tesla::Crypto.session_key(
        @private_key,
        new_vehicle_public_key
      )

    session_info =
      Struct.new(
        :public_key,
        :epoch,
        :counter,
        :clock_time
      ).new(
        Tesla::Crypto.encoded_public_key(
          new_vehicle_key
        ),
        old_session.epoch,
        20,
        old_session.clock_time + 10
      )

    request_uuid =
      "U" * 16

    session_info_bytes =
      "SESSION_INFO"

    def test_signature_type_can_be_encoded_as_single_byte
      metadata =
        Metadata.new
          .put(0, [6].pack("C"))
          .serialize

      assert_equal(
        "000106ff",
        metadata.unpack1("H*")
      )
    end

    metadata =
      Tesla::Metadata.new
        .put_byte(
          Tesla::VehicleCommand::TAG_SIGNATURE_TYPE,
          Tesla::VehicleCommand::SIGNATURE_TYPE_HMAC
        )
        .put(
          Tesla::VehicleCommand::TAG_PERSONALIZATION,
          VIN
        )
        .put(
          Tesla::VehicleCommand::TAG_CHALLENGE,
          request_uuid
        )

    expected_tag =
      Tesla::Crypto.hmac_sha256(
        Tesla::Crypto.session_info_key(
          new_session_key
        ),
        metadata.serialize + session_info_bytes
      )

    protobuf =
      FakeProtobufAdapter.new(
        fault: :MESSAGEFAULT_ERROR_INVALID_TOKEN_OR_COUNTER,
        session_info: session_info_bytes,
        request_uuid: request_uuid,
        session_info_tag: expected_tag
      )

    protobuf.define_singleton_method(
      :decode_session_info
    ) { |_bytes| session_info }

    protobuf.define_singleton_method(
      :session_public_key
    ) { |info| info.public_key }

    protobuf.define_singleton_method(
      :session_epoch
    ) { |info| info.epoch }

    protobuf.define_singleton_method(
      :session_counter
    ) { |info| info.counter }

    protobuf.define_singleton_method(
      :session_clock_time
    ) { |info| info.clock_time }

    setup_command(
      protobuf: protobuf,
      transport: FakeTransport.new(
        response: Base64.strict_encode64("ERROR")
      ),
      session: old_session
    )

    SecureRandom.stub(
      :random_bytes,
      request_uuid
    ) do
      assert_raises(Tesla::ProtocolError) do
        @command.send_authenticated_command(:LOCK)
      end
    end

    assert_equal(
      old_session.epoch,
      @command.session.epoch
    )

    # SessionInfo reports counter 20. The retried command consumes
    # counter 21.
    assert_equal(
      21,
      @command.session.current_counter
    )

    assert_equal(
      new_session_key,
      @command.session.session_key
    )
  end

  def test_piggybacked_session_info_does_not_rollback_counter
    old_session =
      build_session

    old_counter =
      old_session.current_counter

    new_vehicle_key =
      Tesla::Crypto.generate_key

    new_vehicle_public_key =
      Tesla::Crypto.public_key_from_bytes(
        Tesla::Crypto.encoded_public_key(
          new_vehicle_key
        )
      )

    new_session_key =
      Tesla::Crypto.session_key(
        @private_key,
        new_vehicle_public_key
      )

    session_info =
      Struct.new(
        :public_key,
        :epoch,
        :counter,
        :clock_time
      ).new(
        Tesla::Crypto.encoded_public_key(
          new_vehicle_key
        ),
        old_session.epoch,
        old_counter - 1,
        old_session.clock_time + 10
      )

    request_uuid =
      "U" * 16

    session_info_bytes =
      "SESSION_INFO"

    metadata =
      Tesla::Metadata.new
        .put_byte(
          Tesla::VehicleCommand::TAG_SIGNATURE_TYPE,
          Tesla::VehicleCommand::SIGNATURE_TYPE_HMAC
        )
        .put(
          Tesla::VehicleCommand::TAG_PERSONALIZATION,
          VIN
        )
        .put(
          Tesla::VehicleCommand::TAG_CHALLENGE,
          request_uuid
        )

    tag =
      Tesla::Crypto.hmac_sha256(
        Tesla::Crypto.session_info_key(
          new_session_key
        ),
        metadata.serialize + session_info_bytes
      )

    protobuf =
      FakeProtobufAdapter.new(
        fault: :MESSAGEFAULT_ERROR_INVALID_TOKEN_OR_COUNTER,
        session_info: session_info_bytes,
        request_uuid: request_uuid,
        session_info_tag: tag
      )

    protobuf.define_singleton_method(
      :decode_session_info
    ) { |_bytes| session_info }

    protobuf.define_singleton_method(
      :session_public_key
    ) { |info| info.public_key }

    protobuf.define_singleton_method(
      :session_epoch
    ) { |info| info.epoch }

    protobuf.define_singleton_method(
      :session_counter
    ) { |info| info.counter }

    protobuf.define_singleton_method(
      :session_clock_time
    ) { |info| info.clock_time }

    setup_command(
      protobuf: protobuf,
      transport: FakeTransport.new(
        response: Base64.strict_encode64("ERROR")
      ),
      session: old_session
    )

    SecureRandom.stub(
      :random_bytes,
      request_uuid
    ) do
      assert_raises(Tesla::ProtocolError) do
        @command.send_authenticated_command(:LOCK)
      end
    end

    # The first attempt consumes old_counter + 1.
    # Recovery must not roll that counter backward.
    # The retry then consumes old_counter + 2.
    assert_equal(
      old_counter + 2,
      @command.session.current_counter
    )
  end

  def test_piggybacked_session_info_allows_counter_reset_when_epoch_changes
    old_session =
      build_session

    new_epoch =
      "N" * 16

    new_vehicle_key =
      Tesla::Crypto.generate_key

    new_vehicle_public_key =
      Tesla::Crypto.public_key_from_bytes(
        Tesla::Crypto.encoded_public_key(
          new_vehicle_key
        )
      )

    new_session_key =
      Tesla::Crypto.session_key(
        @private_key,
        new_vehicle_public_key
      )

    session_info =
      Struct.new(
        :public_key,
        :epoch,
        :counter,
        :clock_time
      ).new(
        Tesla::Crypto.encoded_public_key(
          new_vehicle_key
        ),
        new_epoch,
        1,
        100
      )

    request_uuid =
      "U" * 16

    session_info_bytes =
      "SESSION_INFO"

    metadata =
      Tesla::Metadata.new
        .put_byte(
          Tesla::VehicleCommand::TAG_SIGNATURE_TYPE,
          Tesla::VehicleCommand::SIGNATURE_TYPE_HMAC
        )
        .put(
          Tesla::VehicleCommand::TAG_PERSONALIZATION,
          VIN
        )
        .put(
          Tesla::VehicleCommand::TAG_CHALLENGE,
          request_uuid
        )

    tag =
      Tesla::Crypto.hmac_sha256(
        Tesla::Crypto.session_info_key(
          new_session_key
        ),
        metadata.serialize + session_info_bytes
      )

    protobuf =
      FakeProtobufAdapter.new(
        fault: :MESSAGEFAULT_ERROR_INCORRECT_EPOCH,
        session_info: session_info_bytes,
        request_uuid: request_uuid,
        session_info_tag: tag
      )

    protobuf.define_singleton_method(
      :decode_session_info
    ) { |_bytes| session_info }

    protobuf.define_singleton_method(
      :session_public_key
    ) { |info| info.public_key }

    protobuf.define_singleton_method(
      :session_epoch
    ) { |info| info.epoch }

    protobuf.define_singleton_method(
      :session_counter
    ) { |info| info.counter }

    protobuf.define_singleton_method(
      :session_clock_time
    ) { |info| info.clock_time }

    setup_command(
      protobuf: protobuf,
      transport: FakeTransport.new(
        response: Base64.strict_encode64("ERROR")
      ),
      session: old_session
    )

    SecureRandom.stub(
      :random_bytes,
      request_uuid
    ) do
      assert_raises(Tesla::ProtocolError) do
        @command.send_authenticated_command(:LOCK)
      end
    end

    assert_equal(
      new_epoch,
      @command.session.epoch
    )

    # The new epoch permits the counter to reset to 1.
    # The retry then consumes counter 2.
    assert_equal(
      2,
      @command.session.current_counter
    )
  end

  def test_invalid_piggybacked_session_info_is_rejected
    session =
      build_session

    request_uuid =
      "U" * 16

    session_info =
      Struct.new(
        :public_key,
        :epoch,
        :counter,
        :clock_time
      ).new(
        Tesla::Crypto.encoded_public_key(
          Tesla::Crypto.generate_key
        ),
        session.epoch,
        100,
        session.clock_time + 10
      )

    protobuf =
      FakeProtobufAdapter.new(
        fault: :MESSAGEFAULT_ERROR_INVALID_TOKEN_OR_COUNTER,
        session_info: "SESSION_INFO",
        request_uuid: request_uuid,
        session_info_tag: "\x00".b * 32
      )

    protobuf.define_singleton_method(
      :decode_session_info
    ) { |_bytes| session_info }

    protobuf.define_singleton_method(
      :session_public_key
    ) { |info| info.public_key }

    protobuf.define_singleton_method(
      :session_epoch
    ) { |info| info.epoch }

    protobuf.define_singleton_method(
      :session_counter
    ) { |info| info.counter }

    protobuf.define_singleton_method(
      :session_clock_time
    ) { |info| info.clock_time }

    setup_command(
      protobuf: protobuf,
      transport: FakeTransport.new(
        response: Base64.strict_encode64("ERROR")
      ),
      session: session
    )

    SecureRandom.stub(
      :random_bytes,
      request_uuid
    ) do
      assert_raises(Tesla::AuthenticationError) do
        @command.send_authenticated_command(:LOCK)
      end
    end

    assert_nil(
      @command.session
    )
  end

  def test_piggybacked_session_info_with_wrong_request_uuid_is_rejected
    request_uuid =
      "U" * 16

    setup_command(
      protobuf:
        FakeProtobufAdapter.new(
          fault: :MESSAGEFAULT_ERROR_INVALID_TOKEN_OR_COUNTER,
          session_info: "SESSION_INFO",
          request_uuid: "R" * 16,
          session_info_tag: "\x00".b * 32
        ),
      transport: FakeTransport.new(
        response: Base64.strict_encode64("ERROR")
      )
    )

    SecureRandom.stub(
      :random_bytes,
      request_uuid
    ) do
      assert_raises(Tesla::ProtocolError) do
        @command.send_authenticated_command(:LOCK)
      end
    end
  end

  def test_cached_session_is_loaded_before_establishing_new_session
    cache_directory =
      Dir.mktmpdir("tesla-cache")

    begin
      session_cache =
        Tesla::SessionCache.new(
          File.join(
            cache_directory,
            "session.json"
          )
        )

      original_session =
        build_session(
          counter: 50
        )

      session_cache.save(
        original_session
      )

      setup_command(
        transport: FakeTransport.new(
          response: Base64.strict_encode64("RESPONSE")
        ),
        session: original_session,
        session_cache: session_cache
      )

      @command.send(
        :ensure_session
      )

      refute_nil(
        @command.session
      )

      assert_equal(
        original_session.session_key,
        @command.session.session_key
      )

      assert_equal(
        50,
        @command.session.current_counter
      )

      assert_empty(
        @protobuf.calls.select do |call|
          call.first == :build_session_info_request
        end
      )
    ensure
      FileUtils.remove_entry(
        cache_directory
      )
    end
  end

  def test_session_cache_is_advanced_before_command_transmission
    cache_directory =
      Dir.mktmpdir("tesla-cache")

    begin
      session_cache =
        Tesla::SessionCache.new(
          File.join(
            cache_directory,
            "session.json"
          )
        )

      session =
        build_session(
          counter: 50
        )

      session_cache.save(session)

      setup_command(
        transport: FakeTransport.new(
          response: Base64.strict_encode64("RESPONSE")
        ),
        session: session,
        session_cache: session_cache
      )

      @command.send_rke_action(
        Tesla::VehicleCommand::RKE_ACTION_LOCK
      )

      data =
        session_cache.load

      assert_equal(
        51,
        data.fetch("counter")
      )
    ensure
      FileUtils.remove_entry(
        cache_directory
      )
    end
  end

  def test_corrupt_session_cache_causes_fresh_session
    cache_directory =
      Dir.mktmpdir("tesla-cache")

    begin
      cache_path =
        File.join(
          cache_directory,
          "session.json"
        )

      File.write(
        cache_path,
        "THIS IS NOT JSON"
      )

      session_cache =
        Tesla::SessionCache.new(
          cache_path
        )

      setup_command(
        transport: FakeTransport.new(
          response: Base64.strict_encode64("SESSION_RESPONSE")
        ),
        session_cache: session_cache
      )
      @command.instance_variable_set(:@session, nil)

      #
      # ensure_session will discard the bad cache.
      #
      assert_raises(
        Tesla::ProtocolError,
        "a corrupt cache should cause fresh session establishment"
      ) do
        @command.send(
          :ensure_session
        )
      end

      assert_nil(
        session_cache.load
      )
    ensure
      FileUtils.remove_entry(
        cache_directory
      )
    end
  end

  def test_authenticated_requests_use_new_request_uuid
    setup_command()

    command_bytes =
      @protobuf.encode_unsigned_message(
        :LOCK
      )

    @command.send(
      :build_authenticated_routable,
      command_bytes
    )

    @command.send(
      :build_authenticated_routable,
      command_bytes
    )

    requests =
      @protobuf.calls
        .select do |call|
          call.first == :build_hmac_routable
        end
        .map do |call|
          call.last.fetch(:uuid)
        end

    assert_equal(
      2,
      requests.length
    )

    refute_equal(
      requests[0],
      requests[1]
    )
  end

  def test_command_reserves_session_counter_before_transport_request
    events = []

    session_cache = Class.new do
      def initialize(session, events)
        @session = session
        @events = events
      end

      def reserve_counter(
        private_key:,
        session:
      )
        @events << :reserve_counter

        @session.advance_counter

        @session
      end
    end.new(
      @session,
      events
    )

    transport = Class.new do
      def initialize(events)
        @events = events
      end

      def signed_command(**kwargs)
        @events << :transport
        { response: Base64.strict_encode64("RESPONSE") }
      end
    end.new(events)

    setup_command(
      session_cache: session_cache,
      transport: transport
    )

    @command.door_lock

    assert_equal(
      [
        :reserve_counter,
        :transport
      ],
      events
    )
  end

  def test_missing_piggybacked_session_info_tag_is_rejected
    setup_command(
      protobuf:
        FakeProtobufAdapter.new(
          fault: :MESSAGEFAULT_ERROR_INVALID_TOKEN_OR_COUNTER,
          session_info: "SESSION_INFO",
          request_uuid: "U" * 16,
          session_info_tag: nil
        )
    )

    result =
      SecureRandom.stub(
        :random_bytes,
        "U" * 16
      ) do
        @command.send(
          :recover_from_session_info,
          :response_message,
          request_uuid: "U" * 16,
          fault: :MESSAGEFAULT_ERROR_INVALID_TOKEN_OR_COUNTER
        )
      end

    assert_equal(
      false,
      result
    )

    assert_same(
      @session,
      @command.session
    )
  end

  def test_failed_piggyback_recovery_discards_session
    setup_command(
      protobuf:
        FakeProtobufAdapter.new(
          fault: :MESSAGEFAULT_ERROR_INVALID_TOKEN_OR_COUNTER,
          session_info: "SESSION_INFO",
          request_uuid: "U" * 16,
          session_info_tag: nil
        )
    )

    @command.define_singleton_method(:ensure_session) do
      raise Tesla::ProtocolError,
            "fresh session required"
    end

    assert_raises(Tesla::ProtocolError) do
      SecureRandom.stub(
        :random_bytes,
        "U" * 16
      ) do
        @command.send_authenticated_command(:LOCK)
      end
    end

    assert_nil(
      @command.session
    )
  end

  private

  def build_session(
    counter: 10,
    clock_time: 1_000,
    epoch: "E" * 16,
    routing_address: "R" * 16
  )
    vehicle_key =
      Tesla::Crypto.generate_key

    vehicle_public_key =
      Tesla::Crypto.public_key_from_bytes(
        Tesla::Crypto.encoded_public_key(
          vehicle_key
        )
      )

    session_key =
      Tesla::Crypto.session_key(
        @private_key,
        vehicle_public_key
      )

    Tesla::Session.new(
      private_key: @private_key,
      vehicle_public_key: vehicle_public_key,
      session_key: session_key,
      epoch: epoch,
      counter: counter,
      clock_time: clock_time,
      routing_address: routing_address
    )
  end

  def valid_gcm_tag(
    key: @session.session_key,
    nonce: "3".b * 12,
    aad: +"".b
  )
    cipher = OpenSSL::Cipher.new("aes-128-gcm")
    cipher.encrypt

    cipher.key = key
    cipher.iv = nonce
    cipher.auth_data = aad

    cipher.final

    cipher.auth_tag
  end

  def encrypt_aes_gcm(key:, iv:, plaintext:, aad:)
    cipher = OpenSSL::Cipher.new("aes-128-gcm")
    cipher.encrypt

    cipher.key = key
    cipher.iv = iv
    cipher.auth_data = aad

    ciphertext = cipher.update(plaintext) + cipher.final
    tag = cipher.auth_tag

    [ciphertext, tag]
  end

  def test_close_trunk_builds_close_rear_trunk_command
    unsigned_message = nil

    @command.define_singleton_method(
      :send_authenticated_command
    ) do |message, **_|
      unsigned_message = message
      :response_message
    end

    result = @command.close_trunk

    assert_equal(
      :response_message,
      result
    )

    refute_nil unsigned_message
    refute_nil unsigned_message.closureMoveRequest

    assert_equal(
      :CLOSURE_MOVE_TYPE_CLOSE,
      unsigned_message.closureMoveRequest.rearTrunk
    )

    assert_nil unsigned_message.RKEAction
  end

  def test_send_authenticated_command_rejects_missing_response
    @transport.stub(
      :signed_command,
      { error: "Unable to parse response" }
    ) do
      error =
        assert_raises(Tesla::ProtocolError) do
          @command.send(
            :send_authenticated_command,
            :action
          )
        end

      assert_equal(
        "signed command response is missing response field",
        error.message
      )
    end
  end

end
