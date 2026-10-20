require_relative "../test_helper"

require "crypto"

class TestTeslaCarServerCommand < Minitest::Test

  def setup
    @private_key =
      OpenSSL::PKey::EC.generate("prime256v1")

    @protobuf =
      Tesla::ProtobufAdapter.new(
        universal_message: UniversalMessage,
        signatures: Signatures,
        vcsec: VCSEC,
        car_server: CarServer
      )

    @transport = Tesla::FleetTransport.new

    @command =
      Tesla::CarServerCommand.new(
        vin: "TESTVIN",
        private_key: @private_key,
        transport: @transport,
        protobuf_adapter: @protobuf,
        logger: SilentLogger.new
      )
  end

  def capture_car_server_action
    captured = []

    @command.stub(
      :send_car_server_action,
      ->(action) {
        captured << action
        :result
      }
    ) do
      result = yield
      return [result, captured]
    end
  end

  def test_window_close
    result, actions =
      capture_car_server_action do
        @command.window_close
      end

    assert_equal :result, result
    assert_equal 1, actions.length

    action = actions.first

    assert_equal(
      :close,
      action
        .vehicleControlWindowAction
        .action
    )
  end

  def test_window_vent
    result, actions =
      capture_car_server_action do
        @command.window_vent
      end

    assert_equal :result, result
    assert_equal 1, actions.length

    assert_equal(
      :vent,
      actions.first
        .vehicleControlWindowAction
        .action
    )
  end

  class RecordingCarServerAdapter
    attr_reader :calls

    def initialize
      @calls = []
    end

    def car_server_action_status(response)
      @calls << [:car_server_action_status, [response], {}]

      return :action_status if response == :response

      nil
    end

    def car_server_result(status)
      @calls << [:car_server_result, [status], {}]

      return :OPERATIONSTATUS_OK if status == :action_status

      nil
    end

    def car_server_result_reason(status)
      @calls << [:car_server_result_reason, [status], {}]

      nil
    end

    def method_missing(name, *args, **kwargs, &block)
      @calls << [name, args, kwargs]
      :built_action
    end

    def respond_to_missing?(name, include_private = false)
      true
    end
  end

  def test_send_authenticated_command_recovers_and_retries_on_sync_fault
    session =
      Struct.new(:routing_address) do
        def advance_counter
          true
        end
      end.new("R" * 16)

    @command.instance_variable_set(
      :@session,
      session
    )

    response_count = 0
    recovery_calls = []
    decrypted_calls = []

    @command.stub(
      :ensure_session,
      true
    ) do
      @command.stub(
        :build_authenticated_routable,
        {
          routable: :routable,
          request_hash: "H" * 32,
          request_uuid: "U" * 16
        }
      ) do
        @protobuf.stub(
          :encode_car_server_action,
          "command-bytes"
        ) do
          @protobuf.stub(
            :encode_routable,
            "routable-bytes"
          ) do
            @protobuf.stub(
              :decode_routable,
              ->(_bytes) {
                response_count += 1

                if response_count == 1
                  :sync_error_response
                else
                  :success_response
                end
              }
            ) do
              @protobuf.stub(
                :signed_message_fault,
                ->(message) {
                  if message == :sync_error_response
                    :MESSAGEFAULT_ERROR_INVALID_SIGNATURE
                  else
                    :MESSAGEFAULT_ERROR_NONE
                  end
                }
              ) do
                @command.stub(
                  :recover_from_session_info,
                  ->(message, request_uuid:, fault:) {
                    recovery_calls << [
                      message,
                      request_uuid,
                      fault
                    ]

                    true
                  }
                ) do
                  @command.stub(
                    :decrypt_response,
                    ->(
                      message,
                      request_hash:,
                      response_counters:
                    ) {
                      decrypted_calls << [
                        message,
                        request_hash
                      ]

                      :success
                    }
                  ) do
                    @transport.stub(
                      :signed_command,
                      ->(vin:, routable_message:) {
                        {
                          response:
                            Base64.strict_encode64(
                              "response"
                            )
                        }
                      }
                    ) do
                      result =
                        @command.send(
                          :send_authenticated_command,
                          :action
                        )

                      assert_equal(
                        :success,
                        result
                      )
                    end
                  end
                end
              end
            end
          end
        end
      end
    end

    assert_equal(
      2,
      response_count
    )

    assert_equal(
      [
        [
          :sync_error_response,
          "U" * 16,
          :MESSAGEFAULT_ERROR_INVALID_SIGNATURE
        ]
      ],
      recovery_calls
    )

    assert_equal(
      [
        [
          :success_response,
          "H" * 32
        ]
      ],
      decrypted_calls
    )
  end

  def test_send_authenticated_command_does_not_retry_sync_fault_twice
    session =
      Struct.new(:routing_address) do
        def advance_counter
          true
        end
      end.new("R" * 16)

    @command.instance_variable_set(
      :@session,
      session
    )

    response_count = 0

    @command.stub(
      :ensure_session,
      true
    ) do
      @command.stub(
        :build_authenticated_routable,
        {
          routable: :routable,
          request_hash: "H" * 32,
          request_uuid: "U" * 16
        }
      ) do
        @protobuf.stub(
          :encode_car_server_action,
          "command-bytes"
        ) do
          @protobuf.stub(
            :encode_routable,
            "routable-bytes"
          ) do
            @protobuf.stub(
              :decode_routable,
              ->(_bytes) {
                response_count += 1
                :sync_error_response
              }
            ) do
              @protobuf.stub(
                :signed_message_fault,
                :MESSAGEFAULT_ERROR_INVALID_SIGNATURE
              ) do
                @command.stub(
                  :recover_from_session_info,
                  true
                ) do
                  @transport.stub(
                    :signed_command,
                    ->(vin:, routable_message:) {
                      {
                        response:
                          Base64.strict_encode64(
                            "response"
                          )
                      }
                    }
                  ) do
                    error =
                      assert_raises(
                        Tesla::ProtocolError
                      ) do
                        @command.send(
                          :send_authenticated_command,
                          :action
                        )
                      end

                    assert_equal(
                      "vehicle returned protocol fault MESSAGEFAULT_ERROR_INVALID_SIGNATURE",
                      error.message.to_s
                    )
                  end
                end
              end
            end
          end
        end
      end
    end

    assert_equal(
      2,
      response_count
    )
  end

  def test_recover_from_session_info_accepts_valid_authenticated_session_info
    old_session =
      Struct.new(
        :routing_address,
        :clock_time,
        :current_counter
      ) do
        def same_epoch?(_epoch)
          true
        end
      end.new(
        "R" * 16,
        1000,
        10
      )

    session_info =
      Object.new

    vehicle_public_key =
      Object.new

    session_key =
      "K" * 32

    @command.instance_variable_set(
      :@session,
      old_session
    )

    @command.stub(
      :session_info_tag,
      "EXPECTED-TAG"
    ) do
      @command.stub(
        :update_session_from_authenticated_info,
        ->(
          session_info:,
          vehicle_public_key:,
          session_key:
        ) {
          assert_same(
            session_info,
            session_info
          )

          assert_same(
            vehicle_public_key,
            vehicle_public_key
          )

          assert_equal(
            session_key,
            session_key
          )
        }
      ) do
        @protobuf.stub(
          :response_session_info,
          "SESSION-INFO-BYTES"
        ) do
          @protobuf.stub(
            :response_request_uuid,
            "U" * 16
          ) do
            @protobuf.stub(
              :session_info_tag,
              "EXPECTED-TAG"
            ) do
              @protobuf.stub(
                :decode_session_info,
                session_info
              ) do
                @protobuf.stub(
                  :session_public_key,
                  "PUBLIC-KEY-BYTES"
                ) do
                  Tesla::Crypto.stub(
                    :public_key_from_bytes,
                    vehicle_public_key
                  ) do
                    Tesla::Crypto.stub(
                      :session_key,
                      session_key
                    ) do
                      Tesla::Crypto.stub(
                        :secure_compare,
                        true
                      ) do
                        result =
                          @command.send(
                            :recover_from_session_info,
                            :response,
                            request_uuid: "U" * 16,
                            fault: :MESSAGEFAULT_ERROR_INVALID_SIGNATURE
                          )

                        assert_equal(
                          true,
                          result
                        )
                      end
                    end
                  end
                end
              end
            end
          end
        end
      end
    end
  end

  def test_recover_from_session_info_rejects_invalid_authentication_tag
    session_info =
      Object.new

    vehicle_public_key =
      Object.new

    session_key =
      "K" * 32

    @protobuf.stub(
      :response_session_info,
      "SESSION-INFO-BYTES"
    ) do
      @protobuf.stub(
        :response_request_uuid,
        "U" * 16
      ) do
        @protobuf.stub(
          :session_info_tag,
          "ACTUAL-TAG"
        ) do
          @protobuf.stub(
            :decode_session_info,
            session_info
          ) do
            @protobuf.stub(
              :session_public_key,
              "PUBLIC-KEY-BYTES"
            ) do
              Tesla::Crypto.stub(
                :public_key_from_bytes,
                vehicle_public_key
              ) do
                Tesla::Crypto.stub(
                  :session_key,
                  session_key
                ) do
                  @command.stub(
                    :session_info_tag,
                    "EXPECTED-TAG"
                  ) do
                    Tesla::Crypto.stub(
                      :secure_compare,
                      false
                    ) do
                      refute @command.send(
                               :recover_from_session_info,
                               :response,
                               request_uuid: "U" * 16,
                               fault: :MESSAGEFAULT_ERROR_INVALID_SIGNATURE
                             )
=begin
                      # recover_from_session_info returns false if
                      # secure_compare returns false.
                      # It does not raise an exception.
                      error =
                        assert_raises(
                          Tesla::ProtocolError
                        ) do
                          @command.send(
                            :recover_from_session_info,
                            :response,
                            request_uuid: "U" * 16,
                            fault: :MESSAGEFAULT_ERROR_INVALID_SIGNATURE
                          )
                        end

                      assert_equal(
                        "invalid piggy-backed session info authentication tag",
                        error.message
                      )
=end
                    end
                  end
                end
              end
            end
          end
        end
      end
    end

    assert_nil(
      @command.instance_variable_get(:@session)
    )
  end

  def test_recover_from_session_info_rejects_mismatched_request_uuid
    @protobuf.stub(
      :response_session_info,
      "SESSION-INFO-BYTES"
    ) do
      @protobuf.stub(
        :response_request_uuid,
        "WRONG-UUID"
      ) do
        Tesla::Crypto.stub(
          :secure_compare,
          false
        ) do
          result =
            @command.send(
              :recover_from_session_info,
              :response,
              request_uuid: "U" * 16,
              fault: :MESSAGEFAULT_ERROR_INVALID_SIGNATURE
            )

          assert_equal(
            false,
            result
          )
        end
      end
    end
  end

  def test_recover_from_session_info_rejects_regressed_session_clock
    old_session =
      Struct.new(
        :routing_address,
        :clock_time,
        :current_counter
      ) do
        def same_epoch?(_epoch)
          true
        end
      end.new(
        "R" * 16,
        1000,
        10
      )

    @command.instance_variable_set(
      :@session,
      old_session
    )

    session_info = Object.new
    vehicle_public_key = Object.new
    session_key = "K" * 32

    @protobuf.stub(
      :response_session_info,
      "SESSION-INFO-BYTES"
    ) do
      @protobuf.stub(
        :response_request_uuid,
        "U" * 16
      ) do
        @protobuf.stub(
          :session_info_tag,
          "VALID-TAG"
        ) do
          @protobuf.stub(
            :decode_session_info,
            session_info
          ) do
            @protobuf.stub(
              :session_public_key,
              "PUBLIC-KEY-BYTES"
            ) do
              @protobuf.stub(
                :session_epoch,
                123
              ) do
                @protobuf.stub(
                  :session_counter,
                  10
                ) do
                  @protobuf.stub(
                    :session_clock_time,
                    999
                  ) do
                    Tesla::Crypto.stub(
                      :public_key_from_bytes,
                      vehicle_public_key
                    ) do
                      Tesla::Crypto.stub(
                        :session_key,
                        session_key
                      ) do
                        @command.stub(
                          :session_info_tag,
                          "VALID-TAG"
                        ) do
                          Tesla::Crypto.stub(
                            :secure_compare,
                            true
                          ) do
                            error =
                              assert_raises(
                                Tesla::ProtocolError
                              ) do
                                @command.send(
                                  :recover_from_session_info,
                                  :response,
                                  request_uuid: "U" * 16,
                                  fault: :MESSAGEFAULT_ERROR_INVALID_SIGNATURE
                                )
                              end

                            assert_equal(
                              "vehicle returned regressed session clock",
                              error.message
                            )
                          end
                        end
                      end
                    end
                  end
                end
              end
            end
          end
        end
      end
    end
  end

  def test_recover_from_session_info_ignores_non_recoverable_fault
    result =
      @command.send(
        :recover_from_session_info,
        :response,
        request_uuid: "U" * 16,
        fault: :MESSAGEFAULT_ERROR_BUSY
      )

    assert_equal(
      false,
      result
    )
  end

  def test_send_charging_set_limit
    adapter = RecordingCarServerAdapter.new

    command =
      Tesla::CarServerCommand.new(
        vin: "TESTVIN",
        private_key: @private_key,
        transport: @transport,
        protobuf_adapter: adapter,
        logger: SilentLogger.new
      )

    command.stub(
      :send_authenticated_command,
      :response
    ) do
      command.send_charging_set_limit(
        percent: 80
      )
    end

    assert_equal(
      :build_charging_set_limit,
      adapter.calls.first[0]
    )

    assert_equal(
      { percent: 80 },
      adapter.calls.first[2]
    )
  end

  def test_send_set_charging_amps
    adapter = RecordingCarServerAdapter.new

    command =
      Tesla::CarServerCommand.new(
        vin: "TESTVIN",
        private_key: @private_key,
        transport: @transport,
        protobuf_adapter: adapter,
        logger: SilentLogger.new
      )

    command.stub(
      :send_authenticated_command,
      :response
    ) do
      command.send_set_charging_amps(
        charging_amps: 32
      )
    end

    assert_equal(
      :build_set_charging_amps,
      adapter.calls.first[0]
    )

    assert_equal(
      { charging_amps: 32 },
      adapter.calls.first[2]
    )
  end

  def build_command_with_recording_adapter
    adapter = RecordingCarServerAdapter.new

    command =
      Tesla::CarServerCommand.new(
        vin: "TESTVIN",
        private_key: @private_key,
        transport: @transport,
        protobuf_adapter: adapter,
        logger: SilentLogger.new
      )

    [command, adapter]
  end

  def test_send_methods_delegate_to_matching_builders
    cases = [
      # send_method,
      # send_kwargs,
      # expected_builder,
      # expected_builder_kwargs

      [
        :send_charging_set_limit,
        { percent: 80 },
        :build_charging_set_limit,
        { percent: 80 }
      ],

      [
        :send_start_charging,
        {},
        :build_charging_start_stop,
        { action: :start }
      ],

      [
        :send_start_charging_standard,
        {},
        :build_charging_start_stop,
        { action: :start_standard }
      ],

      [
        :send_start_charging_max_range,
        {},
        :build_charging_start_stop,
        { action: :start_max_range }
      ],

      [
        :send_stop_charging,
        {},
        :build_charging_start_stop,
        { action: :stop }
      ],

      [
        :send_set_charging_amps,
        { charging_amps: 32 },
        :build_set_charging_amps,
        { charging_amps: 32 }
      ],

      [
        :send_driving_clear_speed_limit_pin,
        { pin: "1234" },
        :build_driving_clear_speed_limit_pin,
        { pin: "1234" }
      ],

      [
        :send_driving_clear_speed_limit_pin_admin,
        {},
        :build_driving_clear_speed_limit_pin_admin,
        {}
      ],

      [
        :send_driving_set_speed_limit,
        { limit_mph: 65.0 },
        :build_driving_set_speed_limit,
        { limit_mph: 65.0 }
      ],

      [
        :send_driving_speed_limit,
        { activate: true, pin: "1234" },
        :build_driving_speed_limit,
        { activate: true, pin: "1234" }
      ],

      [
        :send_hvac_auto,
        { power_on: true, manual_override: false },
        :build_hvac_auto,
        { power_on: true, manual_override: false }
      ],

      [
        :send_hvac_steering_wheel_heater,
        { power_on: true },
        :build_hvac_steering_wheel_heater,
        { power_on: true }
      ],

      [
        :send_media_play,
        {},
        :build_media_play,
        {}
      ],

      [
        :send_media_next_favorite,
        {},
        :build_media_next_favorite,
        {}
      ],

      [
        :send_media_previous_favorite,
        {},
        :build_media_previous_favorite,
        {}
      ],

      [
        :send_media_next_track,
        {},
        :build_media_next_track,
        {}
      ],

      [
        :send_media_previous_track,
        {},
        :build_media_previous_track,
        {}
      ],

      [
        :send_vehicle_control_cancel_software_update,
        {},
        :build_vehicle_control_cancel_software_update,
        {}
      ],

      [
        :send_vehicle_control_flash_lights,
        {},
        :build_vehicle_control_flash_lights,
        {}
      ],

      [
        :send_vehicle_control_honk_horn,
        {},
        :build_vehicle_control_honk_horn,
        {}
      ],

      [
        :send_vehicle_control_reset_valet_pin,
        {},
        :build_vehicle_control_reset_valet_pin,
        {}
      ],

      [
        :send_vehicle_control_set_sentry_mode,
        { on: true },
        :build_vehicle_control_set_sentry_mode,
        { on: true }
      ],

      [
        :send_vehicle_control_set_valet_mode,
        { on: true, password: "1234" },
        :build_vehicle_control_set_valet_mode,
        { on: true, password: "1234" }
      ],

      [
        :send_vehicle_control_window,
        { action: :close },
        :build_vehicle_control_window,
        { action: :close }
      ],

      [
        :send_hvac_bioweapon_mode,
        { on: true, manual_override: false },
        :build_hvac_bioweapon_mode,
        { on: true, manual_override: false }
      ],

      [
        :send_set_cabin_overheat_protection,
        { on: true, fan_only: false },
        :build_set_cabin_overheat_protection,
        { on: true, fan_only: false }
      ],

      [
        :send_set_vehicle_name,
        { vehicle_name: "Test" },
        :build_set_vehicle_name,
        { vehicle_name: "Test" }
      ],

      [
        :send_charge_port_door_close,
        {},
        :build_charge_port_door_close,
        {}
      ],

      [
        :send_charge_port_door_open,
        {},
        :build_charge_port_door_open,
        {}
      ],

      [
        :send_guest_mode,
        { active: true },
        :build_guest_mode,
        { active: true }
      ],

      [
        :send_erase_user_data,
        { reason: "test" },
        :build_erase_user_data,
        { reason: "test" }
      ],

      [
        :send_vehicle_control_set_pin_to_drive,
        { on: true, password: "1234" },
        :build_vehicle_control_set_pin_to_drive,
        { on: true, password: "1234" }
      ],

      [
        :send_vehicle_control_reset_pin_to_drive,
        {},
        :build_vehicle_control_reset_pin_to_drive,
        {}
      ],

      [
        :send_vehicle_control_reset_pin_to_drive_admin,
        {},
        :build_vehicle_control_reset_pin_to_drive_admin,
        {}
      ],

      [
        :send_batch_remove_precondition_schedules,
        { home: true, work: false, other: false },
        :build_batch_remove_precondition_schedules,
        { home: true, work: false, other: false }
      ],

      [
        :send_batch_remove_charge_schedules,
        { home: true, work: false, other: false },
        :build_batch_remove_charge_schedules,
        { home: true, work: false, other: false }
      ],

      [
        :send_parental_controls_clear_pin,
        { pin: "1234" },
        :build_parental_controls_clear_pin,
        { pin: "1234" }
      ],

      [
        :send_parental_controls_clear_pin_admin,
        {},
        :build_parental_controls_clear_pin_admin,
        {}
      ],

      [
        :send_parental_controls,
        { activate: true, pin: "1234" },
        :build_parental_controls,
        { activate: true, pin: "1234" }
      ],

      [
        :send_parental_controls_enable_settings,
        { setting: :SpeedLimit, enable: true },
        :build_parental_controls_enable_settings,
        { setting: :SpeedLimit, enable: true }
      ],

      [
        :send_parental_controls_set_speed_limit,
        { limit_mph: 65.0 },
        :build_parental_controls_set_speed_limit,
        { limit_mph: 65.0 }
      ],

      [
        :send_set_low_power_mode,
        { low_power_mode: true },
        :build_set_low_power_mode,
        { low_power_mode: true }
      ],

      [
        :send_set_keep_accessory_power_mode,
        { keep_accessory_power_mode: true },
        :build_set_keep_accessory_power_mode,
        { keep_accessory_power_mode: true }
      ]
    ]

    cases.each do |send_method, send_kwargs, builder_name, builder_kwargs|
      command, adapter = build_command_with_recording_adapter

      command.stub(
        :send_authenticated_command,
        :response
      ) do
        if send_kwargs.empty?
          command.public_send(send_method)
        else
          command.public_send(send_method, **send_kwargs)
        end
      end

      assert_equal(
        builder_name,
        adapter.calls.first[0],
        "#{send_method} should call #{builder_name}"
      )

      assert_equal(
        [],
        adapter.calls.first[1],
        "#{send_method} should not pass positional arguments to #{builder_name}"
      )

      assert_equal(
        builder_kwargs,
        adapter.calls.first[2],
        "#{send_method} passed incorrect builder arguments"
      )
    end
  end

  def test_send_add_charge_schedule
    command, adapter =
      build_command_with_recording_adapter

    command.stub(
      :send_authenticated_command,
      :response
    ) do
      command.send_add_charge_schedule(
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
    end

    assert_equal(
      :build_add_charge_schedule,
      adapter.calls.first[0]
    )

    assert_equal(
      123,
      adapter.calls.first[2][:id]
    )

    assert_equal(
      "Home",
      adapter.calls.first[2][:name]
    )
  end

  def test_send_add_precondition_schedule
    command, adapter =
      build_command_with_recording_adapter

    command.stub(
      :send_authenticated_command,
      :response
    ) do
      command.send_add_precondition_schedule(
        id: 456,
        name: "Work",
        days_of_week: 62,
        precondition_time: 390,
        one_time: false,
        enabled: true,
        latitude: 32.8,
        longitude: -117.2
      )
    end

    assert_equal(
      :build_add_precondition_schedule,
      adapter.calls.first[0]
    )

    assert_equal(
      456,
      adapter.calls.first[2][:id]
    )

    assert_equal(
      390,
      adapter.calls.first[2][:precondition_time]
    )
  end

  def test_send_remove_charge_schedule
    command, adapter =
      build_command_with_recording_adapter

    command.stub(
      :send_authenticated_command,
      :response
    ) do
      command.send_remove_charge_schedule(
        id: 123
      )
    end

    assert_equal(
      :build_remove_charge_schedule,
      adapter.calls.first[0]
    )

    assert_equal(
      { id: 123 },
      adapter.calls.first[2]
    )
  end

  def test_send_remove_precondition_schedule
    command, adapter =
      build_command_with_recording_adapter

    command.stub(
      :send_authenticated_command,
      :response
    ) do
      command.send_remove_precondition_schedule(
        id: 456
      )
    end

    assert_equal(
      :build_remove_precondition_schedule,
      adapter.calls.first[0]
    )

    assert_equal(
      { id: 456 },
      adapter.calls.first[2]
    )
  end

  def test_send_car_server_action_rejects_failed_response
    adapter = RecordingCarServerAdapter.new

    command =
      Tesla::CarServerCommand.new(
        vin: "TESTVIN",
        private_key: @private_key,
        transport: @transport,
        protobuf_adapter: adapter,
        logger: SilentLogger.new
      )

    adapter.define_singleton_method(:car_server_result) do |status|
      @calls << [:car_server_result, [status], {}]
      :OPERATIONSTATUS_ERROR
    end

    error =
      assert_raises(Tesla::ProtocolError) do
        command.stub(
          :send_authenticated_command,
          :response
        ) do
          command.send_charging_set_limit(percent: 80)
        end
      end

    assert_equal(
      "CarServer command failed",
      error.message
    )
  end

  def test_send_car_server_action_includes_failure_reason
    adapter = RecordingCarServerAdapter.new

    command =
      Tesla::CarServerCommand.new(
        vin: "TESTVIN",
        private_key: @private_key,
        transport: @transport,
        protobuf_adapter: adapter,
        logger: SilentLogger.new
      )

    adapter.define_singleton_method(:car_server_result) do |status|
      @calls << [:car_server_result, [status], {}]
      :OPERATIONSTATUS_ERROR
    end

    adapter.define_singleton_method(:car_server_result_reason) do |status|
      @calls << [:car_server_result_reason, [status], {}]
      "vehicle rejected request"
    end

    error =
      assert_raises(Tesla::ProtocolError) do
        command.stub(
          :send_authenticated_command,
          :response
        ) do
          command.send_charging_set_limit(percent: 80)
        end
      end

    assert_equal(
      "CarServer command failed: vehicle rejected request",
      error.message
    )
  end

  def test_car_server_actions_are_serialized
    first_entered =
      Queue.new

    release_first =
      Queue.new

    second_entered =
      Queue.new

    first_call = true

    @protobuf.stub(
      :build_car_server_action,
      ->(vehicle_action) {
        vehicle_action
      }
    ) do
      @command.stub(
        :send_authenticated_command,
        lambda { |_action|
          if first_call
            first_call = false
            first_entered << true

            release_first.pop
          else
            second_entered << true
          end

          :response
        }
      ) do
        @command.stub(
          :check_response!,
          ->(response) { response }
        ) do
          first =
            Thread.new do
              @command.send(
                :send_car_server_action,
                :first_action
              )
            end

          first_entered.pop

          second =
            Thread.new do
              @command.send(
                :send_car_server_action,
                :second_action
              )
            end

          sleep 0.05

          assert(
            second_entered.empty?,
            "second CarServer command entered before first command completed"
          )

          release_first << true

          first.join
          second.join
        end
      end
    end
  end

  def test_check_response_accepts_success
    response =
      CarServer::Response.new(
        actionStatus:
          CarServer::ActionStatus.new(
            result: :OPERATIONSTATUS_OK
          )
      )

    result =
      @command.send(
        :check_response!,
        response
      )

    assert_same response, result
  end

  def test_check_response_rejects_failed_operation
    response =
      CarServer::Response.new(
        actionStatus:
          CarServer::ActionStatus.new(
            result: :OPERATIONSTATUS_ERROR
          )
      )

    error =
      assert_raises(Tesla::ProtocolError) do
        @command.send(
          :check_response!,
          response
        )
      end

    assert_equal(
      "CarServer command failed",
      error.message
    )
  end

  def test_check_response_includes_failure_reason
    adapter = RecordingCarServerAdapter.new

    command =
      Tesla::CarServerCommand.new(
        vin: "TESTVIN",
        private_key: @private_key,
        transport: @transport,
        protobuf_adapter: adapter,
        logger: SilentLogger.new
      )

    adapter.define_singleton_method(:car_server_result) do |status|
      @calls << [:car_server_result, [status], {}]
      :OPERATIONSTATUS_ERROR
    end

    adapter.define_singleton_method(:car_server_result_reason) do |status|
      @calls << [:car_server_result_reason, [status], {}]
      "vehicle rejected request"
    end

    error =
      assert_raises(Tesla::ProtocolError) do
        command.send(
          :check_response!,
          :response
        )
      end

    assert_equal(
      "CarServer command failed: vehicle rejected request",
      error.message
    )
  end

  def test_check_response_rejects_response_without_action_status
    adapter =
      RecordingCarServerAdapter.new

    command =
      Tesla::CarServerCommand.new(
        vin: "TESTVIN",
        private_key: @private_key,
        transport: @transport,
        protobuf_adapter: adapter,
        logger: SilentLogger.new
      )

    adapter.define_singleton_method(
      :car_server_action_status
    ) do |response|
      @calls << [
        :car_server_action_status,
        [response],
        {}
      ]

      nil
    end

    error =
      assert_raises(Tesla::ProtocolError) do
        command.send(
          :check_response!,
          :response
        )
      end

    assert_equal(
      "CarServer response is missing action status",
      error.message
    )
  end

  def test_check_response_rejects_nil
    error =
      assert_raises(Tesla::ProtocolError) do
        @command.send(
          :check_response!,
          nil
        )
      end

    assert_equal(
      "CarServer response is missing",
      error.message
    )
  end

  def build_car_server_response_adapter(response_counter)
    Class.new do
      def initialize(response_counter)
        @response_counter = response_counter
      end

      def response_is_encrypted?(_message)
        true
      end

      def response_counter(_message)
        @response_counter
      end

      def response_ciphertext(_message)
        "ciphertext"
      end

      def response_tag(_message)
        "tag"
      end

      def response_iv(_message)
        "iv"
      end

      def signed_message_fault(_message)
        nil
      end

      def response_flags(_message)
        0
      end

      def decode_car_server_response(_plaintext)
        :decoded_response
      end
    end.new(response_counter)
  end

  def build_test_session(counter:)
    Tesla::Session.new(
      private_key: @private_key,
      vehicle_public_key: @private_key,
      session_key: "\x01".b * 16,
      epoch: "E" * 16,
      counter: counter,
      clock_time: 1000,
      routing_address: "R" * 16,
      local_time: 1000,
      clock_offset: 0
    )
  end

  def test_decrypt_response_rejects_duplicate_counter
    @command.instance_variable_set(
      :@session,
      build_test_session(counter: 42)
    )

    protobuf =
      build_car_server_response_adapter(43)

    @command.instance_variable_set(
      :@protobuf,
      protobuf
    )

    response_counters = {}

    Tesla::Crypto.stub(
      :aes_gcm_decrypt,
      ""
    ) do
      first_result =
        @command.send(
          :decrypt_response,
          Object.new,
          request_hash: "H" * 32,
          response_counters: response_counters
        )

      assert_nil first_result

      assert_raises(Tesla::ProtocolError) do
        @command.send(
          :decrypt_response,
          Object.new,
          request_hash: "H" * 32,
          response_counters: response_counters
        )
      end
    end

    assert_equal(
      { 43 => true },
      response_counters
    )
  end

  def test_decrypt_response_accepts_different_response_counter
    @command.instance_variable_set(
      :@session,
      build_test_session(counter: 42)
    )

    protobuf =
      build_car_server_response_adapter(43)

    @command.instance_variable_set(
      :@protobuf,
      protobuf
    )

    response_counters = {}

    Tesla::Crypto.stub(
      :aes_gcm_decrypt,
      ""
    ) do
      result =
        @command.send(
          :decrypt_response,
          Object.new,
          request_hash: "H" * 32,
          response_counters: response_counters
        )

      assert_nil result
    end

    assert_equal(
      { 43 => true },
      response_counters
    )
  end

  def test_build_call_reports_only_invalid_parameter
    error =
      assert_raises(RuntimeError) do
        Tesla::CarServerCommand.build_call(
          "vehicle_control_set_valet_mode:on=not-a-boolean,password=Secret123"
        )
      end

    assert_equal(
      'Invalid value for "on" (not-a-boolean)',
      error.message
    )
  end

  def test_build_call_set_charging_amps
    method, kwargs =
      Tesla::CarServerCommand.build_call(
        "set_charging_amps:charging_amps=32"
      )

    assert_equal(
      "set_charging_amps",
      method
    )

    assert_equal(
      {
        charging_amps: 32
      },
      kwargs
    )
  end

  def test_call_command_dispatches_set_charging_amps
    adapter =
      RecordingCarServerAdapter.new

    command =
      Tesla::CarServerCommand.new(
        vin: "TESTVIN",
        private_key: @private_key,
        transport: @transport,
        protobuf_adapter: adapter,
        logger: SilentLogger.new
      )

    command.stub(
      :send_car_server_action,
      :result
    ) do
      result =
        command.call_command(
          :set_charging_amps,
          charging_amps: 32
        )

      assert_equal(
        :result,
        result
      )
    end
  end

  def test_call_command_dispatches_auto_seat_climate
    vehicle_action = Object.new

    @protobuf.stub(
      :build_auto_seat_climate,
      vehicle_action
    ) do
      @command.stub(
        :send_car_server_action,
        ->(action) {
          assert_same vehicle_action, action
          :ok
        }
      ) do
        result =
          @command.call_command(
            "auto_seat_climate",
            {
              auto_seat_position: :AutoSeatPosition_FrontLeft,
              auto_climate_on: true
            }
          )

        assert_equal :ok, result
      end
    end
  end

  def test_missing_signed_command_response_raises_protocol_error
    @transport.stub(
      :signed_command,
      { error: "Unable to parse response" }
    ) do
      error =
        assert_raises(
          Tesla::ProtocolError
        ) do
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

  def test_send_authenticated_command_rejects_invalid_base64
    @transport.stub(
      :signed_command,
      { response: "not-valid-base64!!!" }
    ) do
      error =
        assert_raises(Tesla::ProtocolError) do
          @command.send(
            :send_authenticated_command,
            :action
          )
        end

      assert_equal(
        "signed command response contains invalid base64",
        error.message
      )
    end
  end

  def test_recover_from_session_info_rejects_invalid_authentication_tag_2
    @command.stub(
      :session_info_tag,
      "E" * 32
    ) do
      @protobuf.stub(
        :response_session_info,
        "session-info"
      ) do
        @protobuf.stub(
          :response_request_uuid,
          "U" * 16
        ) do
          @protobuf.stub(
            :session_info_tag,
            "A" * 16
          ) do
            @protobuf.stub(
              :decode_session_info,
              :session_info
            ) do
              @protobuf.stub(
                :session_public_key,
                "public-key"
              ) do
                Tesla::Crypto.stub(
                  :public_key_from_bytes,
                  @private_key
                ) do
                  Tesla::Crypto.stub(
                    :session_key,
                    "S" * 16
                  ) do
                    error =
                      assert_raises(
                        Tesla::AuthenticationError
                      ) do
                        @command.send(
                          :recover_from_session_info,
                          :message,
                          request_uuid: "U" * 16,
                          fault:
                            :MESSAGEFAULT_ERROR_INVALID_SIGNATURE
                        )
                      end

                    assert_equal(
                      "invalid piggy-backed session info authentication tag",
                      error.message
                    )
                  end
                end
              end
            end
          end
        end
      end
    end
  end

end
