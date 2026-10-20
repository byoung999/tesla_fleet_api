# frozen_string_literal: true

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

module Tesla

  # Builds and sends authenticated CarServer commands using Tesla's
  # Infotainment-domain signed-command protocol. It owns the session lifecycle,
  # constructs authenticated RoutableMessages, decrypts authenticated
  # responses, and retries commands when the vehicle reports a recoverable
  # session fault.
  #
  # @see https://developers.tesla.com/docs/fleet-api

  class CarServerCommand
    attr_reader :session

    #------------------------------------------------------------------------

    DOMAIN_INFOTAINMENT = 3

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

    # NOTE: start_time, end_time, off_peak_hours_end_time, precondition_time
    #       are number of minutes past midnight
    ACTIONS = {
      charging_start_stop: { action: { 'start': :start, 'start_standard': :start_standard, 'start_max_range': :start_max_range, 'stop': :stop } },
      charging_set_limit: { percent: :integer },
      set_charging_amps: { charging_amps: :integer },
      driving_clear_speed_limit_pin: { pin: :string },
      driving_clear_speed_limit_pin_admin: {},
      driving_set_speed_limit: { limit_mph: :float },
      driving_speed_limit: { activate: :boolean, pin: :string },
      hvac_auto: {power_on: :boolean, manual_override: :boolean },
      hvac_set_preconditioning_max: { on: :boolean, manual_override: :boolean, manual_override_mode: :boolean },
      hvac_steering_wheel_heater: { power_on: :boolean },
      hvac_temperature_adjustment: { delta_celsius: :float, delta_percent: :integer, absolute_celsius: :float, level: :message, hvac_temperature_zone: :message, driver_temp_celsius: :float, passenger_temp_celsius: :float },
      hvac_bioweapon_mode: { on: :boolean, manual_override: :boolean },
      hvac_seat_heater_actions: { seat_heater_level: { 'off': :SEAT_HEATER_OFF, 'low': :SEAT_HEATER_LOW, 'medium': :SEAT_HEATER_MED, 'high': :SEAT_HEATER_HIGH }, seat_position: { 'front_left': :CAR_SEAT_FRONT_LEFT, 'front_right': :CAR_SEAT_FRONT_RIGHT, 'rear_left': :CAR_SEAT_REAR_LEFT, 'rear_left_back': :CAR_SEAT_REAR_LEFT_BACK, 'rear_center': :CAR_SEAT_REAR_CENTER, 'rear_right': :CAR_SEAT_REAR_RIGHT, 'rear_right_back': :CAR_SEAT_REAR_RIGHT_BACK, 'third_row_left': :CAR_SEAT_THIRD_ROW_LEFT, 'third_row_right': :CAR_SEAT_THIRD_ROW_RIGHT } },
      hvac_seat_cooler_actions: { seat_cooler_level: { 'off': :HvacSeatCoolerLevel_Off, 'low': :HvacSeatCoolerLevel_Low, 'medium': :HvacSeatCoolerLevel_Med, 'high': :HvacSeatCoolerLevel_High }, seat_position: { 'front_left': :HvacSeatCoolerPosition_FrontLeft, 'front_right': :HvacSeatCoolerPosition_FrontRight } },
      hvac_climate_keeper: { action: { 'off': :ClimateKeeperAction_Off, 'on': :ClimateKeeperAction_On, 'dog': :ClimateKeeperAction_Dog, 'camp': :ClimateKeeperAction_Camp }, manual_override: :boolean },
      media_play: {},
      media_update_volume: { volume_delta: :integer, volume_absolute_float: :float },
      media_next_favorite: {},
      media_previous_favorite: {},
      media_next_track: {},
      media_previous_track: {},
      vehicle_control_cancel_software_update: {},
      vehicle_control_flash_lights: {},
      vehicle_control_honk_horn: {},
      vehicle_control_reset_valet_pin: {},
      vehicle_control_schedule_software_update: { offset_sec: :integer },
      vehicle_control_set_sentry_mode: { on: :boolean },
      vehicle_control_set_valet_mode: { on: :boolean, password: :string },
      vehicle_control_sunroof: { action: { 'vent': :vent, 'close': :close, 'open': :open }, absolute_level: :integer, delta_level: :integer },
      vehicle_control_trigger_homelink: { latitude: :float, longitude: :float, token: :string },
      vehicle_control_window: { action: {'close': :close, 'vent': :vent } },
      get_nearby_charging_sites: { include_meta_data: :boolean, radius: :integer, count: :integer },
      scheduled_charging: { enabled: :boolean, charging_time: :integer },
      scheduled_departure: { enabled: :boolean, departure_time: :integer, preconditioning_times: { 'all_week': :all_week, 'weekdays': :weekdays }, off_peak_charging_times: { 'all_week': :all_week, 'weekdays': :weekdays }, off_peak_hours_end_time: :integer },
      auto_seat_climate: { auto_seat_position: { 'front_left': :AutoSeatPosition_FrontLeft, 'front_right': :AutoSeatPosition_FrontRight }, auto_climate_on: :boolean },
      set_cabin_overheat_protection: { on: :boolean, fan_only: :boolean },
      set_vehicle_name: { vehicle_name: :string },
      charge_port_door_close: {},
      charge_port_door_open: {},
      guest_mode: { active: :boolean },
      set_cop_temp: { cop_activation_temp: { 'low': :CopActivationTempLow, 'medium': :CopActivationTempMedium, 'high': :CopActivationTempHigh } },
      erase_user_data: { reason: :string },
      vehicle_control_set_pin_to_drive: { on: :boolean, password: :string },
      vehicle_control_reset_pin_to_drive: {},
      vehicle_control_reset_pin_to_drive_admin: {},
      add_charge_schedule: { id: :integer, name: :string, days_of_week: :integer, start_enabled: :boolean, start_time: :integer, end_enabled: :boolean, end_time: :integer, one_time: :boolean, enabled: :boolean, latitude: :float, longitude: :float },
      add_precondition_schedule: { id: :integer, name: :string, days_of_week: :integer, precondition_time: :integer, one_time: :boolean, enabled: :boolean, latitude: :float, longitude: :float },
      remove_charge_schedule: { id: :integer },
      remove_precondition_schedule: { id: :integer },
      batch_remove_precondition_schedules: { home: :boolean, work: :boolean, other: :boolean },
      batch_remove_charge_schedules: { home: :boolean, work: :boolean, other: :boolean },
      parental_controls_clear_pin: { pin: :string },
      parental_controls_clear_pin_admin: {},
      parental_controls: { activate: :boolean, pin: :string },
      parental_controls_enable_settings: { setting: { 'speed_limit': :SpeedLimit, 'acceleration': :Acceleration, 'safety_features': :SafetyFeatures, 'curfew': :Curfew, 'browser_blocked': :BrowserBlocked, 'theater_blocked': :TheaterBlocked, 'arcade_blocked': :ArcadeBlocked } , enable: :boolean },
      parental_controls_set_speed_limit: { limit_mph: :float },
      set_low_power_mode: { low_power_mode: :boolean },
      set_keep_accessory_power_mode: { keep_accessory_power_mode: :boolean },
      #ping: { ping_id: :integer, local_timestamp: :timestamp, last_remote_timestamp: :timestamp },
    }

    ALIASES = {
      windows: :vehicle_control_window
    }

    #------------------------------------------------------------------------

    # Class method to list supported commands.
    #
    # @return [Array<String>] Array of supported commands

    def self.list_commands
      commands = []
      ACTIONS.each do |command, params|
        commands << list_command(command, params)
      end
      ALIASES.each do |alias_sym, command|
        commands << list_command(alias_sym, ACTIONS[command])
      end

      commands
    end

    # Class method to expand the parameters for the specified command.
    #
    # @param  command [Symbol] Command being processed
    # @param  params  [Hash]   Hash of parameters with types
    # @return [String] Full command string

    def self.list_command(command, params)
      command = command.to_s
      unless params.nil?
        separator = ':'
        params.each do |param, type|
          command += separator
          separator = ',' if separator == ':'
          command += "#{param}="
          if type.is_a?(Hash)
            command += type.keys.join('|')
          else
            command += "#{type.to_s}"
          end
        end
      end

      # Show shortcut without action=
      command.sub!(/:action=/, ':')

      command
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
      params = matches[3]

      raise "Invalid command name \"#{method}\"" unless ACTIONS.key?(method.to_sym)

      action = ACTIONS[method.to_sym]

      kwargs = {}
      unless params.nil?
        params = params.split(/\s*,\s*/)

        params.each do |param|
          (key, value) = param.split(/\s*=\s*/)

          # Shortcut to allow users to simply specify the value of an action
          # parameter instead of action=value.
          if value.nil? && action.key?(:action)
            value = key
            key   = :action
          end

          formatted_value  = nil
          param_type = action[key.to_sym]
          case param_type
          when Hash
            formatted_value = param_type[value.to_sym]
          when :integer
            begin
              formatted_value = Integer(value, 10)
            rescue ArgumentError
              raise "Invalid integer value for \"#{key}\""
            end
          when :float
            begin
              formatted_value = Float(value)
            rescue ArgumentError
              raise "Invalid float value for \"#{key}\""
            end
          when :boolean
            case value
            when 'true'
              formatted_value = true
            when 'false'
              formatted_value = false
            end
          when :string
            formatted_value = value
          when nil
            raise "Invalid param \"#{key}\""
          else
            raise "Invalid param type for \"#{key}\""
          end

          if formatted_value.nil?
            raise "Invalid value for \"#{key}\" (#{value})"
          end

          kwargs[key.to_sym] = formatted_value
        end
      end

      [method, kwargs]
    end

    # Class method to call a car service command.
    #
    # @param  tesla_api [TeslaAPI] TeslaAPI instance
    # @param  vin       [String]   VIN associated with request
    # @param  command   [String]   Command to run
    # @param  logger    [Logger]   Logger to use
    # @return [CarServer::Response, nil] Results of method called
    # @raise  [RuntimeError] If any problems encountered running command

    def self.command(tesla_api, vin, command, logger: nil)
      (method, kwargs) = build_call(command)

      private_key_file = Config.find_config_file('private-key.pem')
      private_key      = OpenSSL::PKey::EC.new(File.read(private_key_file))
      transport        = Tesla::FleetTransport.new(tesla_api: tesla_api)
      protobuf         = Tesla::ProtobufAdapter.new

      car_server_command =
        Tesla::CarServerCommand.new(
          vin:              vin,
          private_key:      private_key,
          transport:        transport,
          protobuf_adapter: protobuf,
          logger:           logger
        )

      car_server_command.call_command(method, kwargs)
    end

    #------------------------------------------------------------------------

    # Initializes a CarServer command executor. The private key identifies the
    # application keypair, the transport submits signed messages, the protobuf
    # adapter handles generated bindings, and the optional SessionCache
    # coordinates counters across processes.
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

    # Serializes the CarServer action, reserves a globally safe session
    # counter when a SessionCache is configured, constructs the authenticated
    # RoutableMessage, submits it, decrypts the response, and performs one
    # session-recovery attempt for recoverable protocol faults.
    #
    # @param  [CarServer::Action] action_message Action to perform
    # @param  [Boolean]           retry_on_sync_error Retry if error occurs
    # @return [CarServer::Response] the command result

    def send_authenticated_command(action_message, retry_on_sync_error: true)
      ensure_session

      command_bytes = @protobuf.encode_car_server_action(action_message)

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
            action_message,
            retry_on_sync_error: false
          )
        end

        raise Tesla::ProtocolError.new(
          "vehicle returned protocol fault #{fault}"
        )
      end

      response_counters = {}

      decrypt_response(
        response_message,
        request_hash:      request.fetch(:request_hash),
        response_counters: response_counters
      )
    end

    # Generic method to run the desired method.
    #
    # @param  method [Symbol] Base name of method(s) to run
    # @param  kwargs [Hash{Symbol => Object}]] Keyword arguments for send method
    # @return [CarServer::Response] Results of method called
    # @raise  [RuntimeError] If any problems encountered running command

    def call_command(method, kwargs)
      build_method = "build_#{method}".to_sym
      send_method  = "send_#{method}".to_sym

      if @protobuf.respond_to?(build_method)
        send_car_server_action(@protobuf.send(build_method, **kwargs))
      elsif respond_to?(send_method, true)
        self.send(send_method, **kwargs)
      else
        raise "No implementation for command #{method}"
      end
    end

    #------------------------------------------------------------------------

    # Builds and sends the authenticated `charging set limit` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @param [Integer] percent value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_charging_set_limit(percent:)
      send_car_server_action(
        @protobuf.build_charging_set_limit(
          percent: percent
        )
      )
    end

    # Builds and sends the authenticated `charging start stop` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @param [Symbol] action value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_charging_start_stop(action:)
      send_car_server_action(
        @protobuf.build_charging_start_stop(
          action: action
        )
      )
    end

    # Builds and sends the authenticated `start charging` vehicle operation.
    # Protocol failures are propagated to the caller rather than being
    # converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_start_charging
      send_charging_start_stop(action: :start)
    end

    # Builds and sends the authenticated `start charging standard` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_start_charging_standard
      send_charging_start_stop(action: :start_standard)
    end

    # Builds and sends the authenticated `start charging max range` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_start_charging_max_range
      send_charging_start_stop(action: :start_max_range)
    end

    # Builds and sends the authenticated `stop charging` vehicle operation.
    # Protocol failures are propagated to the caller rather than being
    # converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_stop_charging
      send_charging_start_stop(action: :stop)
    end

    # Builds and sends the authenticated `set charging amps` vehicle operation.
    # Protocol failures are propagated to the caller rather than being
    # converted into a success result.
    #
    # @param [Integer] charging_amps value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_set_charging_amps(charging_amps:)
      send_car_server_action(
        @protobuf.build_set_charging_amps(
          charging_amps: charging_amps
        )
      )
    end

    # Builds and sends the authenticated `driving clear speed limit pin`
    # vehicle operation. Protocol failures are propagated to the caller rather
    # than being converted into a success result.
    #
    # @param [String] pin value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_driving_clear_speed_limit_pin(pin:)
      send_car_server_action(
        @protobuf.build_driving_clear_speed_limit_pin(
          pin: pin
        )
      )
    end

    # Builds and sends the authenticated `driving clear speed limit pin admin`
    # vehicle operation. Protocol failures are propagated to the caller rather
    # than being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_driving_clear_speed_limit_pin_admin
      send_car_server_action(
        @protobuf.build_driving_clear_speed_limit_pin_admin
      )
    end

    # Builds and sends the authenticated `driving set speed limit` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @param [Float] limit_mph value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_driving_set_speed_limit(limit_mph:)
      send_car_server_action(
        @protobuf.build_driving_set_speed_limit(
          limit_mph: limit_mph
        )
      )
    end

    # Builds and sends the authenticated `driving speed limit` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @param [Boolean] activate value used by the operation.
    # @param [String] pin value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_driving_speed_limit(activate:, pin:)
      send_car_server_action(
        @protobuf.build_driving_speed_limit(
          activate: activate,
          pin: pin
        )
      )
    end

    # Builds and sends the authenticated `hvac auto` vehicle operation.
    # Protocol failures are propagated to the caller rather than being
    # converted into a success result.
    #
    # @param [Boolean] power_on value used by the operation.
    # @param [Boolean] manual_override value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_hvac_auto(power_on:, manual_override: false)
      send_car_server_action(
        @protobuf.build_hvac_auto(
          power_on: power_on,
          manual_override: manual_override
        )
      )
    end

    # Builds and sends the authenticated `hvac set preconditioning max` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_hvac_set_preconditioning_max(
      on:,
      manual_override: false,
      manual_override_mode: []
    )
      send_car_server_action(
        @protobuf.build_hvac_set_preconditioning_max(
          on: on,
          manual_override: manual_override,
          manual_override_mode: manual_override_mode
        )
      )
    end

    # Builds and sends the authenticated `hvac steering wheel heater` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @param [Boolean] power_on value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_hvac_steering_wheel_heater(power_on:)
      send_car_server_action(
        @protobuf.build_hvac_steering_wheel_heater(
          power_on: power_on
        )
      )
    end

    # Builds and sends the authenticated `hvac temperature adjustment` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_hvac_temperature_adjustment(
      delta_celsius: nil,
      delta_percent: nil,
      absolute_celsius: nil,
      level: nil,
      hvac_temperature_zone: [],
      driver_temp_celsius: nil,
      passenger_temp_celsius: nil
    )
      send_car_server_action(
        @protobuf.build_hvac_temperature_adjustment(
          delta_celsius: delta_celsius,
          delta_percent: delta_percent,
          absolute_celsius: absolute_celsius,
          level: level,
          hvac_temperature_zone: hvac_temperature_zone,
          driver_temp_celsius: driver_temp_celsius,
          passenger_temp_celsius: passenger_temp_celsius
        )
      )
    end

    # Builds and sends the authenticated `hvac bioweapon mode` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_hvac_bioweapon_mode(
      on:,
      manual_override: false
    )
      send_car_server_action(
        @protobuf.build_hvac_bioweapon_mode(
          on: on,
          manual_override: manual_override
        )
      )
    end

    # Builds and sends the authenticated `hvac seat heater actions` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @param [Hash] actions value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_hvac_seat_heater_actions(actions:)
      send_car_server_action(
        @protobuf.build_hvac_seat_heater_actions(
          actions: actions
        )
      )
    end

    # Builds and sends the authenticated `hvac seat heater` vehicle operation.
    # Protocol failures are propagated to the caller rather than being
    # converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_hvac_seat_heater(
      seat_heater_level:,
      seat_position:
    )
      send_car_server_action(
        @protobuf.build_hvac_seat_heater(
          seat_heater_level: seat_heater_level,
          seat_position: seat_position
        )
      )
    end

    # Builds and sends the authenticated `hvac seat cooler actions` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @param [Hash] actions value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_hvac_seat_cooler_actions(actions:)
      send_car_server_action(
        @protobuf.build_hvac_seat_cooler_actions(
          actions: actions
        )
      )
    end

    # Builds and sends the authenticated `hvac seat cooler` vehicle operation.
    # Protocol failures are propagated to the caller rather than being
    # converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_hvac_seat_cooler(
      seat_cooler_level:,
      seat_position:
    )
      send_car_server_action(
        @protobuf.build_hvac_seat_cooler(
          seat_cooler_level: seat_cooler_level,
          seat_position: seat_position
        )
      )
    end

    # Builds and sends the authenticated `hvac climate keeper` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_hvac_climate_keeper(
      action:,
      manual_override: false
    )
      send_car_server_action(
        @protobuf.build_hvac_climate_keeper(
          action: action,
          manual_override: manual_override
        )
      )
    end

    # Builds and sends the authenticated `media play` vehicle operation.
    # Protocol failures are propagated to the caller rather than being
    # converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_media_play
      send_car_server_action(
        @protobuf.build_media_play
      )
    end

    # Builds and sends the authenticated `media update volume` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_media_update_volume(
      volume_delta: nil,
      volume_absolute_float: nil
    )
      send_car_server_action(
        @protobuf.build_media_update_volume(
          volume_delta: volume_delta,
          volume_absolute_float: volume_absolute_float
        )
      )
    end

    # Builds and sends the authenticated `media next favorite` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_media_next_favorite
      send_car_server_action(
        @protobuf.build_media_next_favorite
      )
    end

    # Builds and sends the authenticated `media previous favorite` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_media_previous_favorite
      send_car_server_action(
        @protobuf.build_media_previous_favorite
      )
    end

    # Builds and sends the authenticated `media next track` vehicle operation.
    # Protocol failures are propagated to the caller rather than being
    # converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_media_next_track
      send_car_server_action(
        @protobuf.build_media_next_track
      )
    end

    # Builds and sends the authenticated `media previous track` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_media_previous_track
      send_car_server_action(
        @protobuf.build_media_previous_track
      )
    end

    # Builds and sends the authenticated `vehicle control cancel software
    # update` vehicle operation. Protocol failures are propagated to the caller
    # rather than being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_vehicle_control_cancel_software_update
      send_car_server_action(
        @protobuf.build_vehicle_control_cancel_software_update
      )
    end

    # Builds and sends the authenticated `vehicle control flash lights` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_vehicle_control_flash_lights
      send_car_server_action(
        @protobuf.build_vehicle_control_flash_lights
      )
    end

    # Builds and sends the authenticated `vehicle control honk horn` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_vehicle_control_honk_horn
      send_car_server_action(
        @protobuf.build_vehicle_control_honk_horn
      )
    end

    # Builds and sends the authenticated `vehicle control reset valet pin`
    # vehicle operation. Protocol failures are propagated to the caller rather
    # than being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_vehicle_control_reset_valet_pin
      send_car_server_action(
        @protobuf.build_vehicle_control_reset_valet_pin
      )
    end

    # Builds and sends the authenticated `vehicle control schedule software
    # update` vehicle operation. Protocol failures are propagated to the caller
    # rather than being converted into a success result.
    #
    # @param [Integer] offset_sec value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_vehicle_control_schedule_software_update(offset_sec:)
      send_car_server_action(
        @protobuf.build_vehicle_control_schedule_software_update(
          offset_sec: offset_sec
        )
      )
    end

    # Builds and sends the authenticated `vehicle control set sentry mode`
    # vehicle operation. Protocol failures are propagated to the caller rather
    # than being converted into a success result.
    #
    # @param [Boolean] on value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_vehicle_control_set_sentry_mode(on:)
      send_car_server_action(
        @protobuf.build_vehicle_control_set_sentry_mode(
          on: on
        )
      )
    end

    # Builds and sends the authenticated `vehicle control set valet mode`
    # vehicle operation. Protocol failures are propagated to the caller rather
    # than being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_vehicle_control_set_valet_mode(
      on:,
      password: ""
    )
      send_car_server_action(
        @protobuf.build_vehicle_control_set_valet_mode(
          on: on,
          password: password
        )
      )
    end

    # Builds and sends the authenticated `vehicle control sunroof` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_vehicle_control_sunroof(
      action: nil,
      absolute_level: nil,
      delta_level: nil
    )
      send_car_server_action(
        @protobuf.build_vehicle_control_sunroof(
          action: action,
          absolute_level: absolute_level,
          delta_level: delta_level
        )
      )
    end

    # Builds and sends the authenticated `vehicle control trigger homelink`
    # vehicle operation. Protocol failures are propagated to the caller rather
    # than being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_vehicle_control_trigger_homelink(
      latitude:,
      longitude:,
      token:
    )
      send_car_server_action(
        @protobuf.build_vehicle_control_trigger_homelink(
          latitude: latitude,
          longitude: longitude,
          token: token
        )
      )
    end

    # Performs the `window close` operation used by the signed-command protocol implementation.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def window_close
      send_vehicle_control_window(action: :close)
    end

    # Performs the `window vent` operation used by the signed-command protocol implementation.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def window_vent
      send_vehicle_control_window(action: :vent)
    end

    # Builds and sends the authenticated `vehicle control window` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @param [Symbol] action value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_vehicle_control_window(action:)
      send_car_server_action(
        @protobuf.build_vehicle_control_window(
          action: action
        )
      )
    end

    # Builds and sends the authenticated `get nearby charging sites` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_get_nearby_charging_sites(
      include_meta_data: false,
      radius: 0,
      count: 0
    )
      send_car_server_action(
        @protobuf.build_get_nearby_charging_sites(
          include_meta_data: include_meta_data,
          radius: radius,
          count: count
        )
      )
    end

    # Builds and sends the authenticated `scheduled charging` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_scheduled_charging(
      enabled:,
      charging_time:
    )
      send_car_server_action(
        @protobuf.build_scheduled_charging(
          enabled: enabled,
          charging_time: charging_time
        )
      )
    end

    # Builds and sends the authenticated `scheduled departure` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_scheduled_departure(
      enabled:,
      departure_time:,
      preconditioning_times: nil,
      off_peak_charging_times: nil,
      off_peak_hours_end_time: nil
    )
      send_car_server_action(
        @protobuf.build_scheduled_departure(
          enabled: enabled,
          departure_time: departure_time,
          preconditioning_times: preconditioning_times,
          off_peak_charging_times: off_peak_charging_times,
          off_peak_hours_end_time: off_peak_hours_end_time
        )
      )
    end

    # Builds and sends the authenticated `auto seat climate` vehicle operation.
    # Protocol failures are propagated to the caller rather than being
    # converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_auto_seat_climate(
      auto_seat_position:,
      auto_climate_on:
    )
      send_car_server_action(
        @protobuf.build_auto_seat_climate(
          auto_seat_position: auto_seat_position,
          auto_climate_on: auto_climate_on
        )
      )
    end

    # Builds and sends the authenticated `set cabin overheat protection`
    # vehicle operation. Protocol failures are propagated to the caller rather
    # than being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_set_cabin_overheat_protection(
      on:,
      fan_only: false
    )
      send_car_server_action(
        @protobuf.build_set_cabin_overheat_protection(
          on: on,
          fan_only: fan_only
        )
      )
    end

    # Builds and sends the authenticated `set vehicle name` vehicle operation.
    # Protocol failures are propagated to the caller rather than being
    # converted into a success result.
    #
    # @param [String] vehicle_name value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_set_vehicle_name(vehicle_name:)
      send_car_server_action(
        @protobuf.build_set_vehicle_name(
          vehicle_name: vehicle_name
        )
      )
    end

    # Builds and sends the authenticated `charge port door close` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_charge_port_door_close
      send_car_server_action(
        @protobuf.build_charge_port_door_close
      )
    end

    # Builds and sends the authenticated `charge port door open` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_charge_port_door_open
      send_car_server_action(
        @protobuf.build_charge_port_door_open
      )
    end

    # Builds and sends the authenticated `guest mode` vehicle operation.
    # Protocol failures are propagated to the caller rather than being
    # converted into a success result.
    #
    # @param [Boolean] active value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_guest_mode(active:)
      send_car_server_action(
        @protobuf.build_guest_mode(
          active: active
        )
      )
    end

    # Builds and sends the authenticated `set cop temp` vehicle operation.
    # Protocol failures are propagated to the caller rather than being
    # converted into a success result.
    #
    # @param [Symbol] cop_activation_temp value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_set_cop_temp(cop_activation_temp:)
      send_car_server_action(
        @protobuf.build_set_cop_temp(
          cop_activation_temp: cop_activation_temp
        )
      )
    end

    # Builds and sends the authenticated `erase user data` vehicle operation.
    # Protocol failures are propagated to the caller rather than being
    # converted into a success result.
    #
    # @param [String] reason value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_erase_user_data(reason:)
      send_car_server_action(
        @protobuf.build_erase_user_data(
          reason: reason
        )
      )
    end

    # Builds and sends the authenticated `vehicle control set pin to drive`
    # vehicle operation. Protocol failures are propagated to the caller rather
    # than being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_vehicle_control_set_pin_to_drive(
      on:,
      password: ""
    )
      send_car_server_action(
        @protobuf.build_vehicle_control_set_pin_to_drive(
          on: on,
          password: password
        )
      )
    end

    # Builds and sends the authenticated `vehicle control reset pin to drive`
    # vehicle operation. Protocol failures are propagated to the caller rather
    # than being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_vehicle_control_reset_pin_to_drive
      send_car_server_action(
        @protobuf.build_vehicle_control_reset_pin_to_drive
      )
    end

    # Builds and sends the authenticated `vehicle control reset pin to drive
    # admin` vehicle operation. Protocol failures are propagated to the caller
    # rather than being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_vehicle_control_reset_pin_to_drive_admin
      send_car_server_action(
        @protobuf.build_vehicle_control_reset_pin_to_drive_admin
      )
    end

    # Builds and sends the authenticated `add charge schedule` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_add_charge_schedule(
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
      send_car_server_action(
        @protobuf.build_add_charge_schedule(
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
      )
    end

    # Builds and sends the authenticated `add precondition schedule` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_add_precondition_schedule(
      id:,
      name:,
      days_of_week:,
      precondition_time:,
      one_time:,
      enabled:,
      latitude:,
      longitude:
    )
      send_car_server_action(
        @protobuf.build_add_precondition_schedule(
          id: id,
          name: name,
          days_of_week: days_of_week,
          precondition_time: precondition_time,
          one_time: one_time,
          enabled: enabled,
          latitude: latitude,
          longitude: longitude
        )
      )
    end

    # Builds and sends the authenticated `remove charge schedule` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @param [Integer] id value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_remove_charge_schedule(id:)
      send_car_server_action(
        @protobuf.build_remove_charge_schedule(
          id: id
        )
      )
    end

    # Builds and sends the authenticated `remove precondition schedule` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @param [Integer] id value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_remove_precondition_schedule(id:)
      send_car_server_action(
        @protobuf.build_remove_precondition_schedule(
          id: id
        )
      )
    end

    # Builds and sends the authenticated `batch remove precondition schedules`
    # vehicle operation. Protocol failures are propagated to the caller rather
    # than being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_batch_remove_precondition_schedules(
      home: false,
      work: false,
      other: false
    )
      send_car_server_action(
        @protobuf.build_batch_remove_precondition_schedules(
          home: home,
          work: work,
          other: other
        )
      )
    end

    # Builds and sends the authenticated `batch remove charge schedules`
    # vehicle operation. Protocol failures are propagated to the caller rather
    # than being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_batch_remove_charge_schedules(
      home: false,
      work: false,
      other: false
    )
      send_car_server_action(
        @protobuf.build_batch_remove_charge_schedules(
          home: home,
          work: work,
          other: other
        )
      )
    end

    # Builds and sends the authenticated `parental controls clear pin` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @param [String] pin value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_parental_controls_clear_pin(pin:)
      send_car_server_action(
        @protobuf.build_parental_controls_clear_pin(
          pin: pin
        )
      )
    end

    # Builds and sends the authenticated `parental controls clear pin admin`
    # vehicle operation. Protocol failures are propagated to the caller rather
    # than being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_parental_controls_clear_pin_admin
      send_car_server_action(
        @protobuf.build_parental_controls_clear_pin_admin
      )
    end

    # Builds and sends the authenticated `parental controls` vehicle operation.
    # Protocol failures are propagated to the caller rather than being
    # converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_parental_controls(
      activate:,
      pin: ""
    )
      send_car_server_action(
        @protobuf.build_parental_controls(
          activate: activate,
          pin: pin
        )
      )
    end

    # Builds and sends the authenticated `parental controls enable settings`
    # vehicle operation. Protocol failures are propagated to the caller rather
    # than being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_parental_controls_enable_settings(
      setting:,
      enable:
    )
      send_car_server_action(
        @protobuf.build_parental_controls_enable_settings(
          setting: setting,
          enable: enable
        )
      )
    end

    # Builds and sends the authenticated `parental controls set speed limit`
    # vehicle operation. Protocol failures are propagated to the caller rather
    # than being converted into a success result.
    #
    # @param [Float] limit_mph value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_parental_controls_set_speed_limit(limit_mph:)
      send_car_server_action(
        @protobuf.build_parental_controls_set_speed_limit(
          limit_mph: limit_mph
        )
      )
    end

    # Builds and sends the authenticated `set low power mode` vehicle
    # operation. Protocol failures are propagated to the caller rather than
    # being converted into a success result.
    #
    # @param [Boolean] low_power_mode value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_set_low_power_mode(low_power_mode:)
      send_car_server_action(
        @protobuf.build_set_low_power_mode(
          low_power_mode: low_power_mode
        )
      )
    end

    # Builds and sends the authenticated `set keep accessory power mode`
    # vehicle operation. Protocol failures are propagated to the caller rather
    # than being converted into a success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_set_keep_accessory_power_mode(
      keep_accessory_power_mode:
    )
      send_car_server_action(
        @protobuf.build_set_keep_accessory_power_mode(
          keep_accessory_power_mode:
            keep_accessory_power_mode
        )
      )
    end

    # Builds and sends the authenticated `ping` vehicle operation. Protocol
    # failures are propagated to the caller rather than being converted into a
    # success result.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_ping(
      ping_id:,
      local_timestamp: nil,
      last_remote_timestamp: nil
    )
      send_car_server_action(
        @protobuf.build_ping(
          ping_id: ping_id,
          local_timestamp: local_timestamp,
          last_remote_timestamp: last_remote_timestamp
        )
      )
    end

    # Performs the CarServer SessionInfo handshake and installs the resulting
    # session only after the vehicle public key, epoch, counter, clock, routing
    # address, and authentication tag have been validated.
    #
    # @return [Tesla::Session] the command result or constructed protocol value.

    def establish_session
      @logger.info("infotainment_session_establishing")

      local_time      = Time.now.to_i
      routing_address = SecureRandom.random_bytes(16)
      request_uuid    = SecureRandom.random_bytes(16)

      request =
        @protobuf.build_session_info_request(
          domain:          DOMAIN_INFOTAINMENT,
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
              "infotainment session establishment response is missing authentication tag"
      end

      session_info_bytes = @protobuf.session_info_bytes(response_message)

      unless session_info_bytes
        raise Tesla::ProtocolError,
              "infotainment session establishment response is missing session info"
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
              "invalid infotainment session info authentication tag"
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
        "infotainment_session_established",
        counter: @session.current_counter
      )

      @session_cache.save(@session) if @session_cache

      @session
    end

    #------------------------------------------------------------------------

    private

    #------------------------------------------------------------------------

    # Ensures the executor has a usable session and routing address. A cached
    # session is preferred when compatible; otherwise a fresh session handshake
    # is performed.
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
              "infotainment_session_restored",
              counter: @session.current_counter
            )

            return @session
          rescue StandardError => error
            @logger.warn("infotainment_session_restore_failed", error: error)
            @session_cache.delete
          end
        end
      end

      establish_session
    end

    # Handles the `info tag` portion of the signed-command session state.
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

    # Performs the `infotainment request hash` operation used by the
    # signed-command protocol implementation.
    #
    # @param [String] tag value used by the operation.
    # @return [String] the command result or constructed protocol value.

    def infotainment_request_hash(tag)
      [SIGNATURE_TYPE_HMAC_PERSONALIZED].pack("C") + tag
    end

    # Builds the final Infotainment-domain RoutableMessage. The metadata binds
    # the command to the session epoch, expiry time, counter, challenge/request
    # hash, and response-encryption flag before HMAC authentication.
    #
    # @param [String] command_bytes value used by the operation.
    # @return [Hash{Symbol => Object}] the command result or constructed protocol value.

    def build_authenticated_routable(command_bytes)
      vehicle_time = @session.vehicle_time
      expires_at   = vehicle_time + COMMAND_LIFETIME
      counter      = @session.current_counter

      metadata = Metadata.new
        .put_byte(TAG_SIGNATURE_TYPE, SIGNATURE_TYPE_HMAC_PERSONALIZED)
        .put_byte(TAG_DOMAIN        , DOMAIN_INFOTAINMENT             )
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
          domain:                    DOMAIN_INFOTAINMENT,
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
        request_hash: infotainment_request_hash(tag),
        request_uuid: uuid,
        counter:      counter
      }
    end

    # Validates response encryption and request binding, rejects duplicate
    # response counters, decrypts AES-GCM ciphertext when required, and decodes
    # the resulting CarServer response.
    #
    # @param [UniversalMessage::RoutableMessage] message value used by the operation.
    # @param [String] request_hash value used by the operation.
    # @param [Hash{Integer => TrueClass}] response_counters value used by the operation.
    # @return [CarServer::Response, nil] the command result or constructed protocol value.

    def decrypt_response(message, request_hash:, response_counters:)
      unless @protobuf.response_is_encrypted?(message)
        bytes = @protobuf.response_ciphertext(message)

        return nil if bytes.nil? || bytes.empty?

        return @protobuf.decode_car_server_response(bytes)
      end

      response_counter = @protobuf.response_counter(message)

      unless response_counter.is_a?(Integer) && response_counter >= 0
        raise Tesla::ProtocolError, "invalid infotainment response counter"
      end

      if response_counters.key?(response_counter)
        raise Tesla::ProtocolError, "replayed infotainment response counter"
      end

      response_counters[response_counter] = true

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
        .put_byte(TAG_DOMAIN         , DOMAIN_INFOTAINMENT            )
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

      @protobuf.decode_car_server_response(plaintext)
    end

    # Processes authenticated piggy-backed session information after a
    # recoverable fault. It updates the session only when the supplied request
    # UUID and fault identify the response as belonging to the failed command.
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

    # Replaces or advances the active session using authenticated SessionInfo
    # while preserving monotonic counter and clock invariants. A cached session
    # is updated after the new state is accepted.
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

    # Performs the `check response` operation used by the signed-command
    # protocol implementation.
    #
    # @return [CarServer::Response] the command result or constructed protocol value.

    def check_response!(response)
      unless response
        raise Tesla::ProtocolError, "CarServer response is missing"
      end

      status = @protobuf.car_server_action_status(response)

      unless status
        raise Tesla::ProtocolError,
              "CarServer response is missing action status"
      end

      result = @protobuf.car_server_result(status)

      unless result == :OPERATIONSTATUS_OK
        reason  = @protobuf.car_server_result_reason(status)
        message = "CarServer command failed"

        unless reason.nil? || reason.empty?
          message = "#{message}: #{reason}"
        end

        raise Tesla::ProtocolError, message
      end

      response
    end

    # Wraps a vehicle action in the CarServer protobuf envelope, serializes and
    # authenticates it, then checks the application-level CarServer status
    # before returning the response.
    #
    # @param [CarServer::VehicleAction] vehicle_action value used by the operation.
    # @return [CarServer::Response] the command result or constructed protocol value.

    def send_car_server_action(vehicle_action)
      @command_mutex.synchronize do
        action   = @protobuf.build_car_server_action(vehicle_action)
        response = send_authenticated_command(action)
        check_response!(response)
      end
    end

    #------------------------------------------------------------------------

  end
end
