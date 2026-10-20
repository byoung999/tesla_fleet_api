# frozen_string_literal: true

require "universal_message_pb"
require "signatures_pb"
require "vcsec_pb"
require "car_server_pb"
require "common_pb"
require "vehicle_pb"
require "google/protobuf/timestamp_pb"

module Tesla

  # Adapter between the signed-command implementation and the generated
  # protobuf classes. It centralizes construction and decoding of VCSEC and
  # CarServer messages so protocol code does not depend directly on generated
  # binding details.
  #
  # @see https://developers.tesla.com/docs/fleet-api

  class ProtobufAdapter

    # Initializes the protobuf adapter with the generated protobuf namespace
    # and optional logger dependencies used by protocol translation.
    #
    # @return [void] the operation result.

    def initialize(
      universal_message: UniversalMessage,
      signatures: Signatures,
      vcsec: VCSEC,
      car_server: CarServer
    )
      @universal_message = universal_message
      @signatures = signatures
      @vcsec = vcsec
      @car_server = car_server
    end

    # Constructs the protobuf SessionInfo request used to establish or
    # synchronize a signed-command session.
    #
    # @return [UniversalMessage::RoutableMessage] the command result or constructed protocol value.

    def build_session_info_request(
      domain:,
      routing_address:,
      public_key:,
      uuid:
    )
      @universal_message::RoutableMessage.new(
        to_destination:
          @universal_message::Destination.new(
            domain: domain
          ),

        from_destination:
          @universal_message::Destination.new(
            routing_address: routing_address
          ),

        session_info_request:
          @universal_message::SessionInfoRequest.new(
            public_key: public_key,
            challenge: uuid
          ),

        uuid: uuid
      )
    end

    # Extracts the serialized SessionInfo payload from a protobuf response.
    #
    # @param [UniversalMessage::RoutableMessage] message value used by the operation.
    # @return [String] the command result or constructed protocol value.

    def session_info_bytes(message)
      message.session_info
    end

    # Decodes raw SessionInfo bytes into the generated protobuf message type.
    #
    # @param [String] bytes value used by the operation.
    # @return [Signatures::SessionInfo] the requested protocol value.

    def decode_session_info(bytes)
      @signatures::SessionInfo.decode(bytes)
    end

    # Extracts the vehicle public key from a decoded SessionInfo message.
    #
    # @param [Signatures::SessionInfo] session_info value used by the operation.
    # @return [String] the command result or constructed protocol value.

    def session_public_key(session_info)
      session_info.publicKey
    end

    # Extracts the vehicle session epoch from a decoded SessionInfo message.
    #
    # @param [Signatures::SessionInfo] session_info value used by the operation.
    # @return [String] the command result or constructed protocol value.

    def session_epoch(session_info)
      session_info.epoch
    end

    # Extracts the vehicle session counter from a decoded SessionInfo message.
    #
    # @param [Signatures::SessionInfo] session_info value used by the operation.
    # @return [Integer] the command result or constructed protocol value.

    def session_counter(session_info)
      session_info.counter
    end

    # Extracts the vehicle clock timestamp from a decoded SessionInfo message.
    #
    # @param [Signatures::SessionInfo] session_info value used by the operation.
    # @return [Integer] the command result or constructed protocol value.

    def session_clock_time(session_info)
      session_info.clock_time
    end

    # Extracts the authentication tag carried by SessionInfo so the caller can
    # verify the vehicle-provided session state before using it.
    #
    # @param [UniversalMessage::RoutableMessage] message value used by the operation.
    # @return [String, nil] the command result or constructed protocol value.

    def session_info_tag(message)
      signature_data = message.signature_data

      return nil unless signature_data

      tag_data = signature_data.session_info_tag

      return nil unless tag_data

      tag_data.tag
    end

    # Builds a VCSEC RKEAction protobuf message for the requested remote-key
    # action.
    #
    # @param [Symbol] action value used by the operation.
    # @return [VCSEC::UnsignedMessage] the command result or constructed protocol value.

    def build_rke_action(action)
      @vcsec::UnsignedMessage.new(
        RKEAction: action
      )
    end

    # Constructs the protobuf representation for the `closure move`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @return [VCSEC::UnsignedMessage] the command result or constructed protocol value.

    def build_closure_move(
      front_driver_door: nil,
      front_passenger_door: nil,
      rear_driver_door: nil,
      rear_passenger_door: nil,
      rear_trunk: nil,
      front_trunk: nil,
      charge_port: nil,
      tonneau: nil
    )
      fields = {}

      fields[:frontDriverDoor   ] = front_driver_door    unless front_driver_door.nil?
      fields[:frontPassengerDoor] = front_passenger_door unless front_passenger_door.nil?
      fields[:rearDriverDoor    ] = rear_driver_door     unless rear_driver_door.nil?
      fields[:rearPassengerDoor ] = rear_passenger_door  unless rear_passenger_door.nil?
      fields[:rearTrunk         ] = rear_trunk           unless rear_trunk.nil?
      fields[:frontTrunk        ] = front_trunk          unless front_trunk.nil?
      fields[:chargePort        ] = charge_port          unless charge_port.nil?
      fields[:tonneau           ] = tonneau              unless tonneau.nil?

      raise ArgumentError, "at least one closure must be specified" if fields.empty?

      closure_move =
        @vcsec::ClosureMoveRequest.new(
          **fields
        )

      @vcsec::UnsignedMessage.new(
        closureMoveRequest: closure_move
      )
    end

    # Wraps a CarServer vehicle action in the generated protobuf message
    # expected by the Infotainment signed-command protocol.
    #
    # @param [CarServer::VehicleAction] vehicle_action value used by the operation.
    # @return [CarServer::Action] the command result or constructed protocol value.

    def build_car_server_action(vehicle_action)
      @car_server::Action.new(
        vehicleAction: vehicle_action
      )
    end

    # Constructs the protobuf representation for the `charging set limit`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @param [Integer] percent value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_charging_set_limit(percent:)
      @car_server::VehicleAction.new(
        chargingSetLimitAction:
          @car_server::ChargingSetLimitAction.new(
            percent: percent
          )
      )
    end

    # Constructs the protobuf representation for the `charging start stop`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @param [Symbol] action value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_charging_start_stop(action:)
      unless %i[start start_standard start_max_range stop].include?(action)
        raise ArgumentError, "invalid charging action: #{action.inspect}"
      end

      @car_server::VehicleAction.new(
        chargingStartStopAction:
          @car_server::ChargingStartStopAction.new(
            action => @car_server::Void.new
          )
      )
    end

    # Constructs the protobuf representation for the `driving clear speed limit
    # pin` CarServer/VCSEC operation. The returned message is intended for
    # later serialization and authenticated transport.
    #
    # @param [String] pin value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_driving_clear_speed_limit_pin(pin:)
      @car_server::VehicleAction.new(
        drivingClearSpeedLimitPinAction:
          @car_server::DrivingClearSpeedLimitPinAction.new(
            pin: pin
          )
      )
    end

    # Constructs the protobuf representation for the `driving clear speed limit
    # pin admin` CarServer/VCSEC operation. The returned message is intended
    # for later serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_driving_clear_speed_limit_pin_admin
      @car_server::VehicleAction.new(
        drivingClearSpeedLimitPinAdminAction:
          @car_server::DrivingClearSpeedLimitPinAdminAction.new
      )
    end

    # Constructs the protobuf representation for the `driving set speed limit`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @param [Float] limit_mph value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_driving_set_speed_limit(limit_mph:)
      @car_server::VehicleAction.new(
        drivingSetSpeedLimitAction:
          @car_server::DrivingSetSpeedLimitAction.new(
            limit_mph: limit_mph
          )
      )
    end

    # Constructs the protobuf representation for the `driving speed limit`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @param [Boolean] activate value used by the operation.
    # @param [String] pin value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_driving_speed_limit(activate:, pin:)
      @car_server::VehicleAction.new(
        drivingSpeedLimitAction:
          @car_server::DrivingSpeedLimitAction.new(
            activate: activate,
            pin: pin
          )
      )
    end

    # Constructs the protobuf representation for the `hvac auto`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @param [Boolean] power_on value used by the operation.
    # @param [Boolean] manual_override value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_hvac_auto(power_on:, manual_override: false)
      @car_server::VehicleAction.new(
        hvacAutoAction:
          @car_server::HvacAutoAction.new(
            power_on: power_on,
            manual_override: manual_override
          )
      )
    end

    # Constructs the protobuf representation for the `hvac set preconditioning
    # max` CarServer/VCSEC operation. The returned message is intended for
    # later serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_hvac_set_preconditioning_max(
      on:,
      manual_override: false,
      manual_override_mode: []
    )
      @car_server::VehicleAction.new(
        hvacSetPreconditioningMaxAction:
          @car_server::HvacSetPreconditioningMaxAction.new(
            on: on,
            manual_override: manual_override,
            manual_override_mode:
              manual_override_mode.is_a?(Array) \
              ? manual_override_mode : [ manual_override_mode ]
          )
      )
    end

    # Constructs the protobuf representation for the `hvac steering wheel
    # heater` CarServer/VCSEC operation. The returned message is intended for
    # later serialization and authenticated transport.
    #
    # @param [Boolean] power_on value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_hvac_steering_wheel_heater(power_on:)
      @car_server::VehicleAction.new(
        hvacSteeringWheelHeaterAction:
          @car_server::HvacSteeringWheelHeaterAction.new(
            power_on: power_on
          )
      )
    end

    # Constructs the protobuf representation for the `hvac temperature
    # adjustment` CarServer/VCSEC operation. The returned message is intended
    # for later serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_hvac_temperature_adjustment(
      delta_celsius: nil,
      delta_percent: nil,
      absolute_celsius: nil,
      level: nil,
      hvac_temperature_zone: [],
      driver_temp_celsius: nil,
      passenger_temp_celsius: nil
    )
      fields = {}

      fields[:delta_celsius] = delta_celsius unless delta_celsius.nil?
      fields[:delta_percent] = delta_percent unless delta_percent.nil?
      fields[:absolute_celsius] = absolute_celsius unless absolute_celsius.nil?
      fields[:level] = level unless level.nil?
      unless hvac_temperature_zone.nil? || hvac_temperature_zone.empty?
        fields[:hvac_temperature_zone] = hvac_temperature_zone.is_a?(Array) \
                                         ?   hvac_temperature_zone          \
                                         : [ hvac_temperature_zone ]
      end
      fields[:driver_temp_celsius] = driver_temp_celsius unless driver_temp_celsius.nil?
      fields[:passenger_temp_celsius] = passenger_temp_celsius unless passenger_temp_celsius.nil?

      raise ArgumentError, "at least one temperature adjustment is required" if fields.empty?

      @car_server::VehicleAction.new(
        hvacTemperatureAdjustmentAction:
          @car_server::HvacTemperatureAdjustmentAction.new(
            **fields
          )
      )
    end

    # Constructs the protobuf representation for the `hvac temperature level`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @param [Symbol] level value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_hvac_temperature_level(level:)
      unless %i[TEMP_UNKNOWN TEMP_MIN TEMP_MAX].include?(level)
        raise ArgumentError, "invalid temperature level: #{level.inspect}"
      end

      temperature =
        @car_server::HvacTemperatureAdjustmentAction::Temperature.new(
          level => @car_server::Void.new
        )

      build_hvac_temperature_adjustment(
        level: temperature
      )
    end

    # Constructs the protobuf representation for the `hvac temperature zone`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @param [Symbol] zone value used by the operation.
    # @return [CarServer::HvacTemperatureAdjustmentAction::HvacTemperatureZone] the command result or constructed protocol value.

    def build_hvac_temperature_zone(zone:)
      unless %i[
        TEMP_ZONE_UNKNOWN
        TEMP_ZONE_FRONT_LEFT
        TEMP_ZONE_FRONT_RIGHT
        TEMP_ZONE_REAR
      ].include?(zone)
        raise ArgumentError, "invalid temperature zone: #{zone.inspect}"
      end

      @car_server::HvacTemperatureAdjustmentAction::HvacTemperatureZone.new(
        zone => @car_server::Void.new
      )
    end

    # Constructs the protobuf representation for the `media play`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_media_play
      @car_server::VehicleAction.new(
        mediaPlayAction:
          @car_server::MediaPlayAction.new
      )
    end

    # Constructs the protobuf representation for the `media update volume`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_media_update_volume(
      volume_delta: nil,
      volume_absolute_float: nil
    )
      if volume_delta.nil? == volume_absolute_float.nil?
        raise ArgumentError,
              "specify exactly one volume adjustment"
      end

      fields =
        if volume_delta
          { volume_delta: volume_delta }
        else
          { volume_absolute_float: volume_absolute_float }
        end

      @car_server::VehicleAction.new(
        mediaUpdateVolume:
          @car_server::MediaUpdateVolume.new(
            **fields
          )
      )
    end

    # Constructs the protobuf representation for the `media next favorite`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_media_next_favorite
      @car_server::VehicleAction.new(
        mediaNextFavorite:
          @car_server::MediaNextFavorite.new
      )
    end

    # Constructs the protobuf representation for the `media previous favorite`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_media_previous_favorite
      @car_server::VehicleAction.new(
        mediaPreviousFavorite:
          @car_server::MediaPreviousFavorite.new
      )
    end

    # Constructs the protobuf representation for the `media next track`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_media_next_track
      @car_server::VehicleAction.new(
        mediaNextTrack:
          @car_server::MediaNextTrack.new
      )
    end

    # Constructs the protobuf representation for the `media previous track`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_media_previous_track
      @car_server::VehicleAction.new(
        mediaPreviousTrack:
          @car_server::MediaPreviousTrack.new
      )
    end

    # Constructs the protobuf representation for the `get nearby charging
    # sites` CarServer/VCSEC operation. The returned message is intended for
    # later serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_get_nearby_charging_sites(
      include_meta_data: false,
      radius: 0,
      count: 0
    )
      @car_server::VehicleAction.new(
        getNearbyChargingSites:
          @car_server::GetNearbyChargingSites.new(
            include_meta_data: include_meta_data,
            radius: radius,
            count: count
          )
      )
    end

    # Constructs the protobuf representation for the `vehicle control cancel
    # software update` CarServer/VCSEC operation. The returned message is
    # intended for later serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_vehicle_control_cancel_software_update
      @car_server::VehicleAction.new(
        vehicleControlCancelSoftwareUpdateAction:
          @car_server::VehicleControlCancelSoftwareUpdateAction.new
      )
    end

    # Constructs the protobuf representation for the `vehicle control flash
    # lights` CarServer/VCSEC operation. The returned message is intended for
    # later serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_vehicle_control_flash_lights
      @car_server::VehicleAction.new(
        vehicleControlFlashLightsAction:
          @car_server::VehicleControlFlashLightsAction.new
      )
    end

    # Constructs the protobuf representation for the `vehicle control honk
    # horn` CarServer/VCSEC operation. The returned message is intended for
    # later serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_vehicle_control_honk_horn
      @car_server::VehicleAction.new(
        vehicleControlHonkHornAction:
          @car_server::VehicleControlHonkHornAction.new
      )
    end

    # Constructs the protobuf representation for the `vehicle control reset
    # valet pin` CarServer/VCSEC operation. The returned message is intended
    # for later serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_vehicle_control_reset_valet_pin
      @car_server::VehicleAction.new(
        vehicleControlResetValetPinAction:
          @car_server::VehicleControlResetValetPinAction.new
      )
    end

    # Constructs the protobuf representation for the `vehicle control schedule
    # software update` CarServer/VCSEC operation. The returned message is
    # intended for later serialization and authenticated transport.
    #
    # @param [Integer] offset_sec value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_vehicle_control_schedule_software_update(offset_sec:)
      @car_server::VehicleAction.new(
        vehicleControlScheduleSoftwareUpdateAction:
          @car_server::VehicleControlScheduleSoftwareUpdateAction.new(
            offset_sec: offset_sec
          )
      )
    end

    # Constructs the protobuf representation for the `vehicle control set
    # sentry mode` CarServer/VCSEC operation. The returned message is intended
    # for later serialization and authenticated transport.
    #
    # @param [Boolean] on value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_vehicle_control_set_sentry_mode(on:)
      @car_server::VehicleAction.new(
        vehicleControlSetSentryModeAction:
          @car_server::VehicleControlSetSentryModeAction.new(
            on: on
          )
      )
    end

    # Constructs the protobuf representation for the `vehicle control set valet
    # mode` CarServer/VCSEC operation. The returned message is intended for
    # later serialization and authenticated transport.
    #
    # @param [Boolean] on value used by the operation.
    # @param [String] password value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_vehicle_control_set_valet_mode(on:, password: "")
      @car_server::VehicleAction.new(
        vehicleControlSetValetModeAction:
          @car_server::VehicleControlSetValetModeAction.new(
            on: on,
            password: password
          )
      )
    end

    # Constructs the protobuf representation for the `vehicle control sunroof`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_vehicle_control_sunroof(
      action: nil,
      absolute_level: nil,
      delta_level: nil
    )
      fields = {}

      unless absolute_level.nil?
        fields[:absolute_level] = absolute_level
      end

      unless delta_level.nil?
        fields[:delta_level] = delta_level
      end

      unless action.nil?
        unless %i[vent close open].include?(action)
          raise ArgumentError,
                "invalid sunroof action: #{action.inspect}"
        end

        fields[action] = @car_server::Void.new
      end

      raise ArgumentError, "sunroof action is required" if fields.empty?

      @car_server::VehicleAction.new(
        vehicleControlSunroofOpenCloseAction:
          @car_server::VehicleControlSunroofOpenCloseAction.new(
            **fields
          )
      )
    end

    # Constructs the protobuf representation for the `vehicle control trigger
    # homelink` CarServer/VCSEC operation. The returned message is intended for
    # later serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_vehicle_control_trigger_homelink(
      latitude:,
      longitude:,
      token:
    )
      location = CarServer::LatLong.new(
        latitude: latitude,
        longitude: longitude
      )
      @car_server::VehicleAction.new(
        vehicleControlTriggerHomelinkAction:
          @car_server::VehicleControlTriggerHomelinkAction.new(
            location: location,
            token: token
          )
      )
    end

    # Constructs the protobuf representation for the `vehicle control window`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @param [Symbol] action value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_vehicle_control_window(action:)
      unless %i[unknown vent close].include?(action)
        raise ArgumentError,
              "invalid window action: #{action.inspect}"
      end

      @car_server::VehicleAction.new(
        vehicleControlWindowAction:
          @car_server::VehicleControlWindowAction.new(
            action => @car_server::Void.new
          )
      )
    end

    # Constructs the protobuf representation for the `hvac bioweapon mode`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @param [Boolean] on value used by the operation.
    # @param [Boolean] manual_override value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_hvac_bioweapon_mode(on:, manual_override: false)
      @car_server::VehicleAction.new(
        hvacBioweaponModeAction:
          @car_server::HvacBioweaponModeAction.new(
            on: on,
            manual_override: manual_override
          )
      )
    end

    # Constructs the protobuf representation for the `hvac seat heater actions`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @param [String] actions value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_hvac_seat_heater_actions(actions:)
      messages =
        actions.map do |action|
          unless action[:level] && action[:position]
            raise ArgumentError,
                  "seat heater action requires level and position"
          end

          level =
            action[:level]

          position =
            action[:position]

          level_fields = {
            level => @car_server::Void.new
          }

          position_fields = {
            position => @car_server::Void.new
          }

          @car_server::HvacSeatHeaterActions::HvacSeatHeaterAction.new(
            **level_fields,
            **position_fields
          )
        end

      @car_server::VehicleAction.new(
        hvacSeatHeaterActions:
          @car_server::HvacSeatHeaterActions.new(
            hvacSeatHeaterAction: messages
          )
      )
    end

    # Constructs the protobuf representation for the `hvac seat heater`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @return [CarServer::HvacSeatHeaterActions] the command result or constructed protocol value.

    def build_hvac_seat_heater(
      seat_heater_level:,
      seat_position:
    )
      action =
        CarServer::HvacSeatHeaterActions_HvacSeatHeaterAction.new(
          seatHeaterLevel: seat_heater_level,
          seatPosition: seat_position
        )

      CarServer::HvacSeatHeaterActions.new(
        hvacSeatHeaterAction: [action]
      )
    end

    # Constructs the protobuf representation for the `hvac seat cooler actions`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @param [String] actions value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_hvac_seat_cooler_actions(actions:)
      messages =
        actions.map do |action|
          @car_server::HvacSeatCoolerActions::HvacSeatCoolerAction.new(
            seat_cooler_level: action.fetch(:level),
            seat_position: action.fetch(:position)
          )
        end

      @car_server::VehicleAction.new(
        hvacSeatCoolerActions:
          @car_server::HvacSeatCoolerActions.new(
            hvacSeatCoolerAction: messages
          )
      )
    end

    # Constructs the protobuf representation for the `hvac seat cooler`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @return [CarServer::HvacSeatCoolerActions] the command result or constructed protocol value.

    def build_hvac_seat_cooler(
      seat_cooler_level:,
      seat_position:
    )
      action = CarServer::HvacSeatCoolerActions_HvacSeatCoolerAction.new(
        seatCoolerLevel: seat_cooler_level,
        seatPosition: seat_position
      )

      CarServer::HvacSeatCoolerActions.new(
        hvacSeatCoolerAction: [action]
      )
    end

    # Constructs the protobuf representation for the `scheduled charging`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @param [Boolean] enabled value used by the operation.
    # @param [Integer] charging_time value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_scheduled_charging(enabled:, charging_time:)
      @car_server::VehicleAction.new(
        scheduledChargingAction:
          @car_server::ScheduledChargingAction.new(
            enabled: enabled,
            charging_time: charging_time
          )
      )
    end

    # Constructs the protobuf representation for the `scheduled departure`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_scheduled_departure(
      enabled:,
      departure_time:,
      preconditioning_times: nil,
      off_peak_charging_times: nil,
      off_peak_hours_end_time: nil
    )
      fields = {
        enabled: enabled,
        departure_time: departure_time
      }

      fields[:preconditioning_times] =
        preconditioning_times unless preconditioning_times.nil?

      fields[:off_peak_charging_times] =
        off_peak_charging_times unless off_peak_charging_times.nil?

      fields[:off_peak_hours_end_time] =
        off_peak_hours_end_time unless off_peak_hours_end_time.nil?

      @car_server::VehicleAction.new(
        scheduledDepartureAction:
          @car_server::ScheduledDepartureAction.new(
            **fields
          )
      )
    end

    # Constructs the protobuf representation for the `set charging amps`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @param [Integer] charging_amps value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_set_charging_amps(charging_amps:)
      @car_server::VehicleAction.new(
        setChargingAmpsAction:
          @car_server::SetChargingAmpsAction.new(
            charging_amps: charging_amps
          )
      )
    end

    # Constructs the protobuf representation for the `hvac climate keeper`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_hvac_climate_keeper(
      action:,
      manual_override: false
    )
      @car_server::VehicleAction.new(
        hvacClimateKeeperAction:
          @car_server::HvacClimateKeeperAction.new(
            ClimateKeeperAction: action,
            manual_override: manual_override
          )
      )
    end

    # Constructs the protobuf representation for the `ping` CarServer/VCSEC
    # operation. The returned message is intended for later serialization and
    # authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_ping(
      ping_id:,
      local_timestamp: nil,
      last_remote_timestamp: nil
    )
      fields = {
        ping_id: ping_id
      }

      fields[:local_timestamp] =
        local_timestamp unless local_timestamp.nil?

      fields[:last_remote_timestamp] =
        last_remote_timestamp unless last_remote_timestamp.nil?

      @car_server::VehicleAction.new(
        ping:
          @car_server::Ping.new(**fields)
      )
    end

    # Constructs the protobuf representation for the `auto seat climate`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @return [CarServer::AutoSeatClimateAction] the command result or constructed protocol value.

    def build_auto_seat_climate(
      auto_seat_position:,
      auto_climate_on:
    )
      car_seat =
        CarServer::AutoSeatClimateAction_CarSeat.new(
          autoSeatPosition: auto_seat_position,
          autoClimateOn: auto_climate_on
        )

      CarServer::AutoSeatClimateAction.new(
        carseat: [car_seat]
      )
    end

    # Constructs the protobuf representation for the `set cabin overheat
    # protection` CarServer/VCSEC operation. The returned message is intended
    # for later serialization and authenticated transport.
    #
    # @param [Boolean] on value used by the operation.
    # @param [Boolean] fan_only value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_set_cabin_overheat_protection(on:, fan_only: false)
      @car_server::VehicleAction.new(
        setCabinOverheatProtectionAction:
          @car_server::SetCabinOverheatProtectionAction.new(
            on: on,
            fan_only: fan_only
          )
      )
    end

    # Constructs the protobuf representation for the `set vehicle name`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @param [String] vehicle_name value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_set_vehicle_name(vehicle_name:)
      @car_server::VehicleAction.new(
        setVehicleNameAction:
          @car_server::SetVehicleNameAction.new(
            vehicleName: vehicle_name
          )
      )
    end

    # Constructs the protobuf representation for the `charge port door close`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_charge_port_door_close
      @car_server::VehicleAction.new(
        chargePortDoorClose:
          @car_server::ChargePortDoorClose.new
      )
    end

    # Constructs the protobuf representation for the `charge port door open`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_charge_port_door_open
      @car_server::VehicleAction.new(
        chargePortDoorOpen:
          @car_server::ChargePortDoorOpen.new
      )
    end

    # Constructs the protobuf representation for the `guest mode`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @param [Boolean] active value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_guest_mode(active:)
      @car_server::VehicleAction.new(
        guestModeAction:
          ::VehicleState::GuestMode.new(
            GuestModeActive: active
          )
      )
    end

    # Constructs the protobuf representation for the `set cop temp`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @param [Symbol] cop_activation_temp value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_set_cop_temp(cop_activation_temp:)
      @car_server::VehicleAction.new(
        setCopTempAction:
          @car_server::SetCopTempAction.new(
            copActivationTemp: cop_activation_temp
          )
      )
    end

    # Constructs the protobuf representation for the `erase user data`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @param [String] reason value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_erase_user_data(reason:)
      @car_server::VehicleAction.new(
        eraseUserDataAction:
          @car_server::EraseUserDataAction.new(
            reason: reason
          )
      )
    end

    # Constructs the protobuf representation for the `vehicle control set pin
    # to drive` CarServer/VCSEC operation. The returned message is intended for
    # later serialization and authenticated transport.
    #
    # @param [Boolean] on value used by the operation.
    # @param [String] password value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_vehicle_control_set_pin_to_drive(on:, password: "")
      @car_server::VehicleAction.new(
        vehicleControlSetPinToDriveAction:
          @car_server::VehicleControlSetPinToDriveAction.new(
            on: on,
            password: password
          )
      )
    end

    # Constructs the protobuf representation for the `vehicle control reset pin
    # to drive` CarServer/VCSEC operation. The returned message is intended for
    # later serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_vehicle_control_reset_pin_to_drive
      @car_server::VehicleAction.new(
        vehicleControlResetPinToDriveAction:
          @car_server::VehicleControlResetPinToDriveAction.new
      )
    end

    # Constructs the protobuf representation for the `vehicle control reset pin
    # to drive admin` CarServer/VCSEC operation. The returned message is
    # intended for later serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_vehicle_control_reset_pin_to_drive_admin
      @car_server::VehicleAction.new(
        vehicleControlResetPinToDriveAdminAction:
          @car_server::VehicleControlResetPinToDriveAdminAction.new
      )
    end

    # Constructs the protobuf representation for the `charge schedule`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @return [CarServer::ChargeSchedule] the command result or constructed protocol value.

    def build_charge_schedule(
      id:,
      name:,
      days_of_week:,
      start_enabled:,
      start_time:,
      end_enabled:,
      end_time:,
      one_time:,
      enabled:,
      latitude:,
      longitude:
    )
      @car_server::ChargeSchedule.new(
        id: id,
        name: name,
        days_of_week: days_of_week,
        start_enabled: start_enabled,
        start_time: start_time,
        end_enabled: end_enabled,
        end_time: end_time,
        one_time: one_time,
        enabled: enabled,
        latitude: latitude,
        longitude: longitude
      )
    end

    # Constructs the protobuf representation for the `precondition schedule`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @return [CarServer::PreconditionSchedule] the command result or constructed protocol value.

    def build_precondition_schedule(
      id:,
      name:,
      days_of_week:,
      precondition_time:,
      one_time:,
      enabled:,
      latitude:,
      longitude:
    )
      @car_server::PreconditionSchedule.new(
        id: id,
        name: name,
        days_of_week: days_of_week,
        precondition_time: precondition_time,
        one_time: one_time,
        enabled: enabled,
        latitude: latitude,
        longitude: longitude
      )
    end

    # Constructs the protobuf representation for the `add charge schedule`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_add_charge_schedule(
      id:,
      name:,
      days_of_week:,
      start_enabled:,
      start_time:,
      end_enabled:,
      end_time:,
      one_time:,
      enabled:,
      latitude:,
      longitude:
    )
      schedule =
        build_charge_schedule(
          id: id,
          name: name,
          days_of_week: days_of_week,
          start_enabled: start_enabled,
          start_time: start_time,
          end_enabled: end_enabled,
          end_time: end_time,
          one_time: one_time,
          enabled: enabled,
          latitude: latitude,
          longitude: longitude
        )

      @car_server::VehicleAction.new(
        addChargeScheduleAction: schedule
      )
    end

    # Constructs the protobuf representation for the `add precondition
    # schedule` CarServer/VCSEC operation. The returned message is intended for
    # later serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_add_precondition_schedule(
      id:,
      name:,
      days_of_week:,
      precondition_time:,
      one_time:,
      enabled:,
      latitude:,
      longitude:
    )
      schedule =
        build_precondition_schedule(
          id: id,
          name: name,
          days_of_week: days_of_week,
          precondition_time: precondition_time,
          one_time: one_time,
          enabled: enabled,
          latitude: latitude,
          longitude: longitude
        )

      @car_server::VehicleAction.new(
        addPreconditionScheduleAction: schedule
      )
    end

    # Constructs the protobuf representation for the `remove charge schedule`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @param [Integer] id value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_remove_charge_schedule(id:)
      @car_server::VehicleAction.new(
        removeChargeScheduleAction:
          @car_server::RemoveChargeScheduleAction.new(
            id: id
          )
      )
    end

    # Constructs the protobuf representation for the `remove precondition
    # schedule` CarServer/VCSEC operation. The returned message is intended for
    # later serialization and authenticated transport.
    #
    # @param [Integer] id value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_remove_precondition_schedule(id:)
      @car_server::VehicleAction.new(
        removePreconditionScheduleAction:
          @car_server::RemovePreconditionScheduleAction.new(
            id: id
          )
      )
    end

    # Constructs the protobuf representation for the `batch remove precondition
    # schedules` CarServer/VCSEC operation. The returned message is intended
    # for later serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_batch_remove_precondition_schedules(
      home: false,
      work: false,
      other: false
    )
      @car_server::VehicleAction.new(
        batchRemovePreconditionSchedulesAction:
          @car_server::BatchRemovePreconditionSchedulesAction.new(
            home: home,
            work: work,
            other: other
          )
      )
    end

    # Constructs the protobuf representation for the `batch remove charge
    # schedules` CarServer/VCSEC operation. The returned message is intended
    # for later serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_batch_remove_charge_schedules(
      home: false,
      work: false,
      other: false
    )
      @car_server::VehicleAction.new(
        batchRemoveChargeSchedulesAction:
          @car_server::BatchRemoveChargeSchedulesAction.new(
            home: home,
            work: work,
            other: other
          )
      )
    end

    # Constructs the protobuf representation for the `parental controls clear
    # pin` CarServer/VCSEC operation. The returned message is intended for
    # later serialization and authenticated transport.
    #
    # @param [String] pin value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_parental_controls_clear_pin(pin:)
      @car_server::VehicleAction.new(
        parentalControlsClearPinAction:
          @car_server::ParentalControlsClearPinAction.new(
            pin: pin
          )
      )
    end

    # Constructs the protobuf representation for the `parental controls clear
    # pin admin` CarServer/VCSEC operation. The returned message is intended
    # for later serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_parental_controls_clear_pin_admin
      @car_server::VehicleAction.new(
        parentalControlsClearPinAdminAction:
          @car_server::ParentalControlsClearPinAdminAction.new
      )
    end

    # Constructs the protobuf representation for the `parental controls`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @param [Boolean] activate value used by the operation.
    # @param [String] pin value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_parental_controls(activate:, pin: "")
      @car_server::VehicleAction.new(
        parentalControlsAction:
          @car_server::ParentalControlsAction.new(
            activate: activate,
            pin: pin
          )
      )
    end

    # Constructs the protobuf representation for the `parental controls enable
    # settings` CarServer/VCSEC operation. The returned message is intended for
    # later serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_parental_controls_enable_settings(
      setting:,
      enable:
    )
      @car_server::VehicleAction.new(
        parentalControlsEnableSettingsAction:
          @car_server::ParentalControlsEnableSettingsAction.new(
            setting: setting,
            enable: enable
          )
      )
    end

    # Constructs the protobuf representation for the `parental controls set
    # speed limit` CarServer/VCSEC operation. The returned message is intended
    # for later serialization and authenticated transport.
    #
    # @param [Float] limit_mph value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_parental_controls_set_speed_limit(limit_mph:)
      @car_server::VehicleAction.new(
        parentalControlsSetSpeedLimitAction:
          @car_server::ParentalControlsSetSpeedLimitAction.new(
            limit_mph: limit_mph
          )
      )
    end

    # Constructs the protobuf representation for the `set low power mode`
    # CarServer/VCSEC operation. The returned message is intended for later
    # serialization and authenticated transport.
    #
    # @param [Boolean] low_power_mode value used by the operation.
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_set_low_power_mode(low_power_mode:)
      @car_server::VehicleAction.new(
        setLowPowerModeAction:
          @car_server::SetLowPowerModeAction.new(
            low_power_mode: low_power_mode
          )
      )
    end

    # Constructs the protobuf representation for the `set keep accessory power
    # mode` CarServer/VCSEC operation. The returned message is intended for
    # later serialization and authenticated transport.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_set_keep_accessory_power_mode(
      keep_accessory_power_mode:
    )
      @car_server::VehicleAction.new(
        setKeepAccessoryPowerModeAction:
          @car_server::SetKeepAccessoryPowerModeAction.new(
            keep_accessory_power_mode:
              keep_accessory_power_mode
          )
      )
    end

    # Serializes an unsigned VCSEC protobuf message into the byte
    # representation used inside a RoutableMessage.
    #
    # @param [UniversalMessage::RoutableMessage] message value used by the operation.
    # @return [String] the command result or constructed protocol value.

    def encode_unsigned_message(message)
      @vcsec::UnsignedMessage.encode(message)
    end

    # Builds a RoutableMessage carrying the supplied command bytes and HMAC
    # metadata for an authenticated signed command.
    #
    # @return [CarServer::VehicleAction] the command result or constructed protocol value.

    def build_hmac_routable(
      domain:,
      routing_address:,
      uuid:,
      protobuf_message_as_bytes:,
      metadata:,
      metadata_bytes:,
      tag:,
      public_key:,
      flags:
    )
      hmac_data =
        @signatures::HMAC_Personalized_Signature_Data.new(
          epoch: metadata.value(3),
          counter: metadata.value(5).unpack1("N"),
          expires_at: metadata.value(4).unpack1("N"),
          tag: tag
        )

      signature_data =
        @signatures::SignatureData.new(
          signer_identity:
            @signatures::KeyIdentity.new(
              public_key: public_key
            ),

          HMAC_Personalized_data: hmac_data
        )

      @universal_message::RoutableMessage.new(
        to_destination:
          @universal_message::Destination.new(
            domain: domain
          ),

        from_destination:
          @universal_message::Destination.new(
            routing_address: routing_address
          ),

        protobuf_message_as_bytes:
          protobuf_message_as_bytes,

        signature_data:
          signature_data,

        uuid: uuid,

        flags: flags
      )
    end

    # Serializes a RoutableMessage protobuf into wire bytes for transport to
    # Tesla Fleet API.
    #
    # @param [UniversalMessage::RoutableMessage] message value used by the operation.
    # @return [String] the command result or constructed protocol value.

    def encode_routable(message)
      @universal_message::RoutableMessage.encode(message)
    end

    # Parses raw RoutableMessage bytes into the generated protobuf representation.
    #
    # @param [String] bytes value used by the operation.
    # @return [UniversalMessage::RoutableMessage] the requested protocol value.

    def decode_routable(bytes)
      @universal_message::RoutableMessage.decode(bytes)
    end

    # Extracts the protocol fault enum from a signed-command response so the
    # command layer can distinguish success from recoverable and fatal faults.
    #
    # @param [UniversalMessage::RoutableMessage] message value used by the operation.
    # @return [Symbol, nil] the command result or constructed protocol value.

    def signed_message_fault(message)
      status = message.signedMessageStatus

      return nil if status.nil?

      status.signed_message_fault
    end

    # Decodes the protobuf command-response envelope from raw response bytes.
    #
    # @param [String] bytes value used by the operation.
    # @return [VCSEC::FromVCSECMessage] the requested protocol value.

    def decode_command_response(bytes)
      @vcsec::FromVCSECMessage.decode(
        bytes
      )
    end

    # Extracts the `is encrypted` field from a decoded vehicle response.
    #
    # @return [Boolean] whether the requested condition is true.

    def response_is_encrypted?(message)
      signature_data = message.signature_data
      return false unless signature_data

      !signature_data.AES_GCM_Response_data.nil?
    end

    # Extracts the encrypted response ciphertext from the decoded response
    # message.
    #
    # @param [UniversalMessage::RoutableMessage] message value used by the operation.
    # @return [String] the command result or constructed protocol value.

    def response_ciphertext(message)
      message.protobuf_message_as_bytes
    end

    # Extracts the response counter used to prevent duplicate or replayed
    # encrypted responses.
    #
    # @param [UniversalMessage::RoutableMessage] message value used by the operation.
    # @return [Integer] the command result or constructed protocol value.

    def response_counter(message)
      response_data =
        message.signature_data&.AES_GCM_Response_data

      raise Tesla::ProtocolError,
            "encrypted response is missing AES-GCM response data" unless response_data

      response_data.counter
    end

    # Extracts the AES-GCM authentication tag from an encrypted response.
    #
    # @param [UniversalMessage::RoutableMessage] message value used by the operation.
    # @return [String] the command result or constructed protocol value.

    def response_tag(message)
      response_data =
        message.signature_data&.AES_GCM_Response_data

      raise Tesla::ProtocolError,
            "encrypted response is missing AES-GCM response data" unless response_data

      response_data.tag
    end

    # Extracts the initialization vector used for AES-GCM response decryption.
    #
    # @param [UniversalMessage::RoutableMessage] message value used by the operation.
    # @return [String] the command result or constructed protocol value.

    def response_iv(message)
      response_data =
        message.signature_data&.AES_GCM_Response_data

      raise Tesla::ProtocolError,
            "encrypted response is missing AES-GCM response data" unless response_data

      response_data.nonce
    end

    # Extracts the response flags that describe response encoding and
    # encryption behavior.
    #
    # @param [UniversalMessage::RoutableMessage] message value used by the operation.
    # @return [Integer] the command result or constructed protocol value.

    def response_flags(message)
      message.flags
    end

    # Extracts the request UUID used to correlate the vehicle response with the
    # authenticated command.
    #
    # @param [UniversalMessage::RoutableMessage] message value used by the operation.
    # @return [String] the command result or constructed protocol value.

    def response_request_uuid(message)
      message.request_uuid
    end

    # Extracts piggy-backed SessionInfo from a response when the vehicle
    # provides updated session state.
    #
    # @param [UniversalMessage::RoutableMessage] message value used by the operation.
    # @return [String, nil] the command result or constructed protocol value.

    def response_session_info(message)
      bytes = message.session_info

      return nil if bytes.nil? || bytes.empty?

      bytes
    end

    # Constructs the protobuf representation for the `vehicle control window
    # action` CarServer/VCSEC operation. The returned message is intended for
    # later serialization and authenticated transport.
    #
    # @return [CarServer::Action] the command result or constructed protocol value.

    def build_vehicle_control_window_action(
      action:
    )
      unless [
        :unknown,
        :vent,
        :close
      ].include?(action)
        raise ArgumentError,
              "invalid window action: #{action.inspect}"
      end

      window_action =
        CarServer::VehicleControlWindowAction.new(
          action => CarServer::Void.new
        )

      vehicle_action =
        CarServer::VehicleAction.new(
          vehicleControlWindowAction: window_action
        )

      CarServer::Action.new(
        vehicleAction: vehicle_action
      )
    end

    # Serializes a CarServer action protobuf into bytes suitable for the
    # authenticated Infotainment command envelope.
    #
    # @param [UniversalMessage::RoutableMessage] message value used by the operation.
    # @return [String] the command result or constructed protocol value.

    def encode_car_server_action(message)
      CarServer::Action.encode(
        message
      )
    end

    # Decodes raw CarServer response bytes into the generated CarServer
    # response protobuf.
    #
    # @param [String] bytes value used by the operation.
    # @return [CarServer::Response] the requested protocol value.

    def decode_car_server_response(bytes)
      CarServer::Response.decode(
        bytes
      )
    end

    # Extracts the application-level action status from a CarServer response.
    #
    # @param [UniversalMessage::RoutableMessage] message value used by the operation.
    # @return [CarServer::ActionStatus, nil] the command result or constructed protocol value.

    def car_server_action_status(message)
      message.actionStatus
    end

    # Maps a CarServer action status into the adapter's normalized result
    # representation.
    #
    # @param [CarServer::ActionStatus] status value used by the operation.
    # @return [Symbol, nil] the command result or constructed protocol value.

    def car_server_result(status)
      return nil unless status

      status.result
    end

    # Extracts the explanatory reason associated with a non-success CarServer
    # action status.
    #
    # @param [CarServer::ActionStatus] status value used by the operation.
    # @return [String, nil] the command result or constructed protocol value.

    def car_server_result_reason(status)
      return nil unless status

      reason =
        status.result_reason

      return nil unless reason

      reason.plain_text
    end

  end
end
