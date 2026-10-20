require_relative "../test_helper"

require "protobuf_adapter"

class TestTeslaProtobufAdapter < Minitest::Test

  def setup
    @adapter =
      Tesla::ProtobufAdapter.new(
        universal_message: UniversalMessage,
        signatures: Signatures,
        vcsec: VCSEC,
        car_server: CarServer
      )
  end


  def test_build_rke_lock_action
    message =
      @adapter.build_rke_action(
        :RKE_ACTION_LOCK
      )

    assert_equal(
      :RKE_ACTION_LOCK,
      message.RKEAction
    )
  end


  def test_build_rke_unlock_action
    message =
      @adapter.build_rke_action(
        :RKE_ACTION_UNLOCK
      )

    assert_equal(
      :RKE_ACTION_UNLOCK,
      message.RKEAction
    )
  end


  def test_encode_unsigned_message
    message =
      @adapter.build_rke_action(
        :RKE_ACTION_LOCK
      )

    encoded =
      @adapter.encode_unsigned_message(
        message
      )

    assert_instance_of(
      String,
      encoded
    )

    refute_empty(encoded)

    decoded =
      VCSEC::UnsignedMessage.decode(
        encoded
      )

    assert_equal(
      :RKE_ACTION_LOCK,
      decoded.RKEAction
    )
  end


  def test_routable_round_trip
    message =
      UniversalMessage::RoutableMessage.new(
        to_destination:
          UniversalMessage::Destination.new(
            domain: :DOMAIN_VEHICLE_SECURITY
          ),

        from_destination:
          UniversalMessage::Destination.new(
            routing_address: "R" * 16
          ),

        uuid: "U" * 16
      )

    encoded =
      @adapter.encode_routable(
        message
      )

    decoded =
      @adapter.decode_routable(
        encoded
      )

    assert_equal(
      "U" * 16,
      decoded.uuid
    )

    assert_equal(
      "R" * 16,
      decoded.from_destination.routing_address
    )

    assert_equal(
      :DOMAIN_VEHICLE_SECURITY,
      decoded.to_destination.domain
    )
  end


  def test_session_info_decoding
    session_info =
      Signatures::SessionInfo.new(
        counter: 123,
        publicKey: "P" * 65,
        epoch: "E" * 16,
        clock_time: 4567
      )

    encoded =
      Signatures::SessionInfo.encode(
        session_info
      )

    decoded =
      @adapter.decode_session_info(
        encoded
      )

    assert_equal(
      123,
      @adapter.session_counter(decoded)
    )

    assert_equal(
      "P" * 65,
      @adapter.session_public_key(decoded)
    )

    assert_equal(
      "E" * 16,
      @adapter.session_epoch(decoded)
    )

    assert_equal(
      4567,
      @adapter.session_clock_time(decoded)
    )
  end


  def test_session_info_tag
    message =
      UniversalMessage::RoutableMessage.new(
        signature_data:
          Signatures::SignatureData.new(
            session_info_tag:
              Signatures::HMAC_Signature_Data.new(
                tag: "T" * 32
              )
          )
      )

    assert_equal(
      "T" * 32,
      @adapter.session_info_tag(message)
    )
  end


  def test_build_session_info_request
    routing_address = "R" * 16
    public_key = "\x04" + ("\x01" * 64)
    uuid = "U" * 16

    message =
      @adapter.build_session_info_request(
        domain: :DOMAIN_VEHICLE_SECURITY,
        routing_address: routing_address,
        public_key: public_key,
        uuid: uuid
      )

    assert_equal(
      :DOMAIN_VEHICLE_SECURITY,
      message.to_destination.domain
    )

    assert_equal(
      routing_address,
      message.from_destination.routing_address
    )

    assert_equal(
      public_key,
      message.session_info_request.public_key
    )

    assert_equal(
      uuid,
      message.session_info_request.challenge
    )

    assert_equal(
      uuid,
      message.uuid
    )
  end


  def test_build_hmac_routable
    metadata =
      Tesla::Metadata.new
        .put(0, 8)
        .put(1, 2)
        .put(2, "5YJTESTVIN1234567")
        .put(3, "E" * 16)
        .put(4, 1234)
        .put(5, 42)
        .put(7, 2)

    tag = "T" * 32
    public_key = "\x04" + ("\x01" * 64)

    message =
      @adapter.build_hmac_routable(
        domain: :DOMAIN_VEHICLE_SECURITY,
        routing_address: "R" * 16,
        uuid: "U" * 16,
        protobuf_message_as_bytes: "COMMAND",
        metadata: metadata,
        metadata_bytes: metadata.serialize,
        tag: tag,
        public_key: public_key,
        flags: 2
      )

    assert_equal(
      :DOMAIN_VEHICLE_SECURITY,
      message.to_destination.domain
    )

    assert_equal(
      "R" * 16,
      message.from_destination.routing_address
    )

    assert_equal(
      "COMMAND",
      message.protobuf_message_as_bytes
    )

    assert_equal(
      "U" * 16,
      message.uuid
    )

    assert_equal(
      2,
      message.flags
    )

    assert_equal(
      public_key,
      message.signature_data.signer_identity.public_key
    )

    hmac =
      message.signature_data.HMAC_Personalized_data

    assert_equal(
      "E" * 16,
      hmac.epoch
    )

    assert_equal(
      42,
      hmac.counter
    )

    assert_equal(
      1234,
      hmac.expires_at
    )

    assert_equal(
      tag,
      hmac.tag
    )
  end


  def test_signed_message_fault
    message =
      UniversalMessage::RoutableMessage.new(
        signedMessageStatus:
          UniversalMessage::MessageStatus.new(
            signed_message_fault:
              :MESSAGEFAULT_ERROR_INVALID_SIGNATURE
          )
      )

    assert_equal(
      :MESSAGEFAULT_ERROR_INVALID_SIGNATURE,
      @adapter.signed_message_fault(message)
    )
  end


  def test_signed_message_fault_is_nil_when_status_absent
    message =
      UniversalMessage::RoutableMessage.new

    assert_nil(
      @adapter.signed_message_fault(message)
    )
  end


  def test_decode_command_response
    response =
      VCSEC::FromVCSECMessage.new(
        commandStatus:
          VCSEC::CommandStatus.new(
            operationStatus:
              :OPERATIONSTATUS_OK
          )
      )

    bytes =
      VCSEC::FromVCSECMessage.encode(
        response
      )

    decoded =
      @adapter.decode_command_response(
        bytes
      )

    assert_equal(
      :OPERATIONSTATUS_OK,
      decoded.commandStatus.operationStatus
    )
  end

  def test_decode_command_response_accepts_protobuf_bytes
    response =
      VCSEC::FromVCSECMessage.new(
        commandStatus:
          VCSEC::CommandStatus.new(
            operationStatus:
              :OPERATIONSTATUS_OK
          )
      )

    bytes =
      VCSEC::FromVCSECMessage.encode(
        response
      )

    decoded =
      @adapter.decode_command_response(
        bytes
      )

    assert_instance_of(
      VCSEC::FromVCSECMessage,
      decoded
    )
  end


  def test_rke_action_round_trip
    message =
      @adapter.build_rke_action(
        :RKE_ACTION_LOCK
      )

    encoded =
      @adapter.encode_unsigned_message(message)

    decoded =
      VCSEC::UnsignedMessage.decode(encoded)

    assert_equal(
      :RKE_ACTION_LOCK,
      decoded.RKEAction
    )
  end

  def test_extracts_aes_gcm_response_data
    nonce = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c".b
    counter = 123
    tag = "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f".b

    message =
      UniversalMessage::RoutableMessage.new(
        signature_data:
          Signatures::SignatureData.new(
            AES_GCM_Response_data:
              Signatures::AES_GCM_Response_Signature_Data.new(
                nonce: nonce,
                counter: counter,
                tag: tag
              )
          )
      )

    assert_equal true,
      @adapter.response_is_encrypted?(message)

    assert_equal counter,
      @adapter.response_counter(message)

    assert_equal tag,
      @adapter.response_tag(message)

    assert_equal nonce,
      @adapter.response_iv(message)
  end

  def test_unencrypted_response_has_no_aes_gcm_response_data
    message =
      UniversalMessage::RoutableMessage.new(
        signature_data:
          Signatures::SignatureData.new
      )

    assert_equal false,
      @adapter.response_is_encrypted?(message)
  end

  def test_encrypted_response_counter_rejects_missing_aes_gcm_data
    message =
      UniversalMessage::RoutableMessage.new(
        signature_data:
          Signatures::SignatureData.new
      )

    assert_raises(Tesla::ProtocolError) do
      @adapter.response_counter(message)
    end
  end

  def test_encrypted_response_tag_rejects_missing_aes_gcm_data
    message =
      UniversalMessage::RoutableMessage.new(
        signature_data:
          Signatures::SignatureData.new
      )

    assert_raises(Tesla::ProtocolError) do
      @adapter.response_tag(message)
    end
  end

  def test_encrypted_response_iv_rejects_missing_aes_gcm_data
    message =
      UniversalMessage::RoutableMessage.new(
        signature_data:
          Signatures::SignatureData.new
      )

    assert_raises(Tesla::ProtocolError) do
      @adapter.response_iv(message)
    end
  end

  def test_response_session_info
    session_info =
      Signatures::SessionInfo.new(
        counter: 123,
        publicKey: "P" * 65,
        epoch: "E" * 16,
        clock_time: 456
      )

    message =
      UniversalMessage::RoutableMessage.new(
        session_info:
          Signatures::SessionInfo.encode(
            session_info
          )
      )

    assert_equal(
      Signatures::SessionInfo.encode(session_info),
      @adapter.response_session_info(message)
    )
  end

  def test_response_session_info_returns_nil_when_absent
    message =
      UniversalMessage::RoutableMessage.new

    assert_nil(
      @adapter.response_session_info(message)
    )
  end

  def test_response_request_uuid
    uuid = "U" * 16

    message =
      UniversalMessage::RoutableMessage.new(
        request_uuid: uuid
      )

    assert_equal(
      uuid,
      @adapter.response_request_uuid(message)
    )
  end

  def test_build_closure_move_open_rear_trunk
    message =
      @adapter.build_closure_move(
        rear_trunk: :CLOSURE_MOVE_TYPE_OPEN
      )

    refute_nil message.closureMoveRequest

    assert_equal(
      :CLOSURE_MOVE_TYPE_OPEN,
      message.closureMoveRequest.rearTrunk
    )
  end

  def test_encode_closure_move_open_rear_trunk
    message =
      @adapter.build_closure_move(
        rear_trunk: :CLOSURE_MOVE_TYPE_OPEN
      )

    encoded =
      @adapter.encode_unsigned_message(
        message
      )

    decoded =
      VCSEC::UnsignedMessage.decode(
        encoded
      )

    refute_nil decoded.closureMoveRequest

    assert_equal(
      :CLOSURE_MOVE_TYPE_OPEN,
      decoded.closureMoveRequest.rearTrunk
    )
  end

  def test_build_closure_move_open_rear_trunk_has_expected_wire_encoding
    message =
      @adapter.build_closure_move(
        rear_trunk: :CLOSURE_MOVE_TYPE_OPEN
      )

    encoded =
      @adapter.encode_unsigned_message(
        message
      )

    assert_equal(
      "22022803",
      encoded.unpack1("H*")
    )
  end

  def test_encode_vehicle_control_window_close
    message =
      @adapter.build_vehicle_control_window_action(
        action: :close
      )

    encoded =
      @adapter.encode_car_server_action(
        message
      )

    decoded =
      CarServer::Action.decode(
        encoded
      )

    window =
      decoded
        .vehicleAction
        .vehicleControlWindowAction

    assert_equal(
      :close,
      window.action
    )
  end

  def test_rejects_invalid_window_action
    assert_raises(
      ArgumentError
    ) do
      @adapter.build_vehicle_control_window_action(
        action: :open
      )
    end
  end

  def test_build_car_server_action
    vehicle_action =
      @adapter.build_vehicle_control_window(
        action: :close
      )

    action =
      @adapter.build_car_server_action(
        vehicle_action
      )

    assert_instance_of(
      CarServer::Action,
      action
    )

    assert_same(
      vehicle_action,
      action.vehicleAction
    )
  end

  def test_build_charging_set_limit
    message =
      @adapter.build_charging_set_limit(
        percent: 80
      )

    assert_equal(
      80,
      message.chargingSetLimitAction.percent
    )
  end

  def test_build_driving_clear_speed_limit_pin
    message =
      @adapter.build_driving_clear_speed_limit_pin(
        pin: "1234"
      )

    assert_equal(
      "1234",
      message.drivingClearSpeedLimitPinAction.pin
    )
  end

  def test_build_driving_set_speed_limit
    message =
      @adapter.build_driving_set_speed_limit(
        limit_mph: 70.5
      )

    assert_in_delta(
      70.5,
      message.drivingSetSpeedLimitAction.limit_mph,
      0.0001
    )
  end

  def test_build_driving_speed_limit
    message =
      @adapter.build_driving_speed_limit(
        activate: true,
        pin: "1234"
      )

    action = message.drivingSpeedLimitAction

    assert_equal true, action.activate
    assert_equal "1234", action.pin
  end

  def test_build_hvac_auto
    message =
      @adapter.build_hvac_auto(
        power_on: true,
        manual_override: true
      )

    action = message.hvacAutoAction

    assert_equal true, action.power_on
    assert_equal true, action.manual_override
  end

  def test_build_hvac_steering_wheel_heater
    message =
      @adapter.build_hvac_steering_wheel_heater(
        power_on: true
      )

    assert_equal(
      true,
      message.hvacSteeringWheelHeaterAction.power_on
    )
  end

  def test_build_set_charging_amps
    message =
      @adapter.build_set_charging_amps(
        charging_amps: 32
      )

    assert_equal(
      32,
      message.setChargingAmpsAction.charging_amps
    )
  end

  def test_build_set_cabin_overheat_protection
    message =
      @adapter.build_set_cabin_overheat_protection(
        on: true,
        fan_only: true
      )

    action = message.setCabinOverheatProtectionAction

    assert_equal true, action.on
    assert_equal true, action.fan_only
  end

  def test_build_set_vehicle_name
    message =
      @adapter.build_set_vehicle_name(
        vehicle_name: "Test Car"
      )

    assert_equal(
      "Test Car",
      message.setVehicleNameAction.vehicleName
    )
  end

  def test_build_erase_user_data
    message =
      @adapter.build_erase_user_data(
        reason: "test"
      )

    assert_equal(
      "test",
      message.eraseUserDataAction.reason
    )
  end

  def test_build_parental_controls_set_speed_limit
    message =
      @adapter.build_parental_controls_set_speed_limit(
        limit_mph: 65.0
      )

    assert_in_delta(
      65.0,
      message.parentalControlsSetSpeedLimitAction.limit_mph,
      0.0001
    )
  end

  def test_build_set_low_power_mode
    message =
      @adapter.build_set_low_power_mode(
        low_power_mode: true
      )

    assert_equal(
      true,
      message.setLowPowerModeAction.low_power_mode
    )
  end

  def test_build_set_keep_accessory_power_mode
    message =
      @adapter.build_set_keep_accessory_power_mode(
        keep_accessory_power_mode: true
      )

    assert_equal(
      true,
      message
        .setKeepAccessoryPowerModeAction
        .keep_accessory_power_mode
    )
  end

  def test_build_charging_start_stop_all_actions
    {
      start: :start,
      start_standard: :start_standard,
      start_max_range: :start_max_range,
      stop: :stop
    }.each do |input, expected|
      message =
        @adapter.build_charging_start_stop(
          action: input
        )

      assert_equal(
        expected,
        message.chargingStartStopAction.charging_action
      )
    end
  end

  def test_build_charging_start_stop_rejects_invalid_action
    assert_raises(ArgumentError) do
      @adapter.build_charging_start_stop(
        action: :bogus
      )
    end
  end

  def test_build_vehicle_control_window_close
    message =
      @adapter.build_vehicle_control_window(
        action: :close
      )

    window =
      message.vehicleControlWindowAction

    assert_equal(
      :close,
      window.action
    )
  end

  def test_build_vehicle_control_window_vent
    message =
      @adapter.build_vehicle_control_window(
        action: :vent
      )

    assert_equal(
      :vent,
      message.vehicleControlWindowAction.action
    )
  end

  def test_build_vehicle_control_window_rejects_invalid_action
    assert_raises(ArgumentError) do
      @adapter.build_vehicle_control_window(
        action: :open
      )
    end
  end


  def test_build_charge_schedule
    schedule =
      @adapter.build_charge_schedule(
        id: 123456789,
        name: "Home",
        days_of_week: 127,
        start_enabled: true,
        start_time: 480,
        end_enabled: true,
        end_time: 1320,
        one_time: false,
        enabled: true,
        latitude: 32.7157,
        longitude: -117.1611
      )

    assert_instance_of(
      CarServer::ChargeSchedule,
      schedule
    )

    assert_equal 123456789, schedule.id
    assert_equal "Home", schedule.name
    assert_equal 127, schedule.days_of_week
    assert_equal true, schedule.start_enabled
    assert_equal 480, schedule.start_time
    assert_equal true, schedule.end_enabled
    assert_equal 1320, schedule.end_time
    assert_equal false, schedule.one_time
    assert_equal true, schedule.enabled

    assert_in_delta(
      32.7157,
      schedule.latitude,
      0.0001
    )

    assert_in_delta(
      -117.1611,
      schedule.longitude,
      0.0001
    )
  end

  def test_build_precondition_schedule
    schedule =
      @adapter.build_precondition_schedule(
        id: 987654321,
        name: "Work",
        days_of_week: 62,
        precondition_time: 420,
        one_time: false,
        enabled: true,
        latitude: 32.8,
        longitude: -117.2
      )

    assert_instance_of(
      CarServer::PreconditionSchedule,
      schedule
    )

    assert_equal 987654321, schedule.id
    assert_equal "Work", schedule.name
    assert_equal 62, schedule.days_of_week
    assert_equal 420, schedule.precondition_time
    assert_equal false, schedule.one_time
    assert_equal true, schedule.enabled

    assert_in_delta(
      32.8,
      schedule.latitude,
      0.0001
    )

    assert_in_delta(
      -117.2,
      schedule.longitude,
      0.0001
    )
  end

  def test_build_add_charge_schedule
    message =
      @adapter.build_add_charge_schedule(
        id: 123,
        name: "Home",
        days_of_week: 127,
        start_enabled: true,
        start_time: 480,
        end_enabled: false,
        end_time: 0,
        one_time: false,
        enabled: true,
        latitude: 32.7,
        longitude: -117.1
      )

    schedule =
      message.addChargeScheduleAction

    assert_instance_of(
      CarServer::ChargeSchedule,
      schedule
    )

    assert_equal 123, schedule.id
    assert_equal "Home", schedule.name
    assert_equal 480, schedule.start_time
    assert_equal true, schedule.start_enabled
    assert_equal false, schedule.end_enabled
  end

  def test_build_add_precondition_schedule
    message =
      @adapter.build_add_precondition_schedule(
        id: 456,
        name: "Work",
        days_of_week: 62,
        precondition_time: 390,
        one_time: false,
        enabled: true,
        latitude: 32.8,
        longitude: -117.2
      )

    schedule =
      message.addPreconditionScheduleAction

    assert_instance_of(
      CarServer::PreconditionSchedule,
      schedule
    )

    assert_equal 456, schedule.id
    assert_equal "Work", schedule.name
    assert_equal 390, schedule.precondition_time
  end

  def test_charge_schedule_round_trip
    original =
      @adapter.build_add_charge_schedule(
        id: 123,
        name: "Home",
        days_of_week: 127,
        start_enabled: true,
        start_time: 480,
        end_enabled: true,
        end_time: 1320,
        one_time: false,
        enabled: true,
        latitude: 32.7157,
        longitude: -117.1611
      )

    encoded =
      @adapter.encode_car_server_action(
        @adapter.build_car_server_action(original)
      )

    decoded =
      CarServer::Action.decode(
        encoded
      )

    schedule =
      decoded
        .vehicleAction
        .addChargeScheduleAction

    assert_equal 123, schedule.id
    assert_equal "Home", schedule.name
    assert_equal 127, schedule.days_of_week
    assert_equal true, schedule.start_enabled
    assert_equal 480, schedule.start_time
    assert_equal true, schedule.end_enabled
    assert_equal 1320, schedule.end_time
    assert_equal false, schedule.one_time
    assert_equal true, schedule.enabled
  end

  def test_precondition_schedule_round_trip
    original =
      @adapter.build_add_precondition_schedule(
        id: 456,
        name: "Work",
        days_of_week: 62,
        precondition_time: 390,
        one_time: false,
        enabled: true,
        latitude: 32.8,
        longitude: -117.2
      )

    encoded =
      @adapter.encode_car_server_action(
        @adapter.build_car_server_action(original)
      )

    decoded =
      CarServer::Action.decode(
        encoded
      )

    schedule =
      decoded
        .vehicleAction
        .addPreconditionScheduleAction

    assert_equal 456, schedule.id
    assert_equal "Work", schedule.name
    assert_equal 62, schedule.days_of_week
    assert_equal 390, schedule.precondition_time
    assert_equal false, schedule.one_time
    assert_equal true, schedule.enabled
  end

end
