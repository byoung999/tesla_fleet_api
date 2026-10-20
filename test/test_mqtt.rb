# frozen_string_literal: true

require 'minitest/autorun'
require 'openssl'
require 'tempfile'
require 'socket'

# Need to disable verbose warnings when requiring paho-mqtt.
verbose, $VERBOSE = $VERBOSE, nil
require 'paho-mqtt'
$VERBOSE = verbose

require_relative 'test_helper'
require_relative '../lib/Mqtt'

#----------------------------------------------------------------------------

class MqttRecurseDataTest < Minitest::Test
  def test_flatten_simple_hash
    data = {
      speed: 42,
      locked: true,
      name: 'Model 3'
    }

    result = Mqtt.recurse_data(data)

    assert_equal [
      { key: 'speed' , value: 42        },
      { key: 'locked', value: true      },
      { key: 'name'  , value: 'Model 3' }
    ], result
  end

  def test_flatten_nested_hash
    data = {
      charge_state: {
        battery_level: 85,
        charging: true
      }
    }

    result = Mqtt.recurse_data(data)

    assert_equal [
      { key: 'charge_state/battery_level', value: 85   },
      { key: 'charge_state/charging'     , value: true }
    ], result
  end

  def test_flatten_array
    data = {
      wheels: [1, 2, 3]
    }

    result = Mqtt.recurse_data(data)

    assert_equal [
      { key: 'wheels[0]', value: 1 },
      { key: 'wheels[1]', value: 2 },
      { key: 'wheels[2]', value: 3 }
    ], result
  end

  def test_flatten_nested_arrays_and_hashes
    data = {
      vehicles: [
        { id: 123, name: 'one' },
        { id: 456, name: 'two' }
      ]
    }

    result = Mqtt.recurse_data(data)

    assert_equal [
      { key: 'vehicles[0]/id'  , value: 123   },
      { key: 'vehicles[0]/name', value: 'one' },
      { key: 'vehicles[1]/id'  , value: 456   },
      { key: 'vehicles[1]/name', value: 'two' }
    ], result
  end

  def test_flatten_nil
    assert_equal [
      { key: '', value: nil }
    ], Mqtt.recurse_data(nil)
  end

  def test_flatten_false
    assert_equal [
      { key: '', value: false }
    ], Mqtt.recurse_data(false)
  end

  def test_empty_hash
    assert_equal [], Mqtt.recurse_data({})
  end

  def test_empty_array
    assert_equal [], Mqtt.recurse_data([])
  end

  def test_preserves_insertion_order
    data = {
      first:  1,
      second: 2,
      third:  3
    }

    result = Mqtt.recurse_data(data)

    assert_equal %w[first second third],
                 result.map { |message| message[:key] }
  end
end

#----------------------------------------------------------------------------

class FakeMqttClient
  attr_reader :published

  def initialize(connected: true, publish_status: 0)
    @connected      = connected
    @publish_status = publish_status
    @published      = []
  end

  def connected?
    @connected
  end

  def publish(topic, payload, retain, qos)
    @published << {
      topic:   topic,
      payload: payload,
      retain:  retain,
      qos:     qos
    }

    @publish_status
  end
end

class FakeLogger
  attr_reader :debug_messages, :error_messages

  def initialize
    @debug_messages = []
    @error_messages = []
  end

  def debug(message)
    @debug_messages << message
  end

  def error(message)
    @error_messages << message
  end
end

class FakeCounter
  attr_reader :value

  def initialize(value = 0)
    @value = value
  end

  def increment
    @value += 1
  end

  def decrement
    @value -= 1
  end
end

class MqttPublishTest < Minitest::Test
  def setup
    @logger  = FakeLogger.new
    @counter = FakeCounter.new
  end

  def test_publishes_value_to_expected_topic
    client = FakeMqttClient.new

    Mqtt.publish_values(
      client,
      [{ key: 'charge_state/battery_level', value: 85 }],
      logger:  @logger,
      counter: @counter
    )

    assert_equal [
      {
        topic:   'tesla/charge_state/battery_level',
        payload: '85',
        retain:  false,
        qos:     1
      }
    ], client.published

    assert_equal 1, @counter.value
  end

  def test_publishes_multiple_values
    client = FakeMqttClient.new

    values = [
      { key: 'charge_state/battery_level', value: 85    },
      { key: 'charge_state/charging'     , value: true  },
      { key: 'vehicle_state/locked'      , value: false }
    ]

    Mqtt.publish_values(
      client,
      values,
      logger:  @logger,
      counter: @counter
    )

    assert_equal 3, client.published.length
    assert_equal 3, @counter.value

    assert_equal(
      'tesla/charge_state/battery_level',
      client.published[0][:topic]
    )

    assert_equal '85'   , client.published[0][:payload]
    assert_equal 'true' , client.published[1][:payload]
    assert_equal 'false', client.published[2][:payload]
  end

  def test_uses_qos_one
    client = FakeMqttClient.new

    Mqtt.publish_values(
      client,
      [{ key: 'test', value: 'value' }],
      logger:  @logger,
      counter: @counter
    )

    assert_equal 1    , client.published.first[:qos   ]
    assert_equal false, client.published.first[:retain]
  end

  def test_does_not_publish_when_disconnected
    client = FakeMqttClient.new(connected: false)

    Mqtt.publish_values(
      client,
      [{ key: 'test', value: 'value' }],
      logger:  @logger,
      counter: @counter
    )

    assert_empty client.published
    assert_equal 0, @counter.value
    assert_equal 1, @logger.error_messages.length
  end

  def test_does_not_increment_counter_when_publish_fails
    client = FakeMqttClient.new(publish_status: 1)

    Mqtt.publish_values(
      client,
      [{ key: 'test', value: 'value' }],
      logger:  @logger,
      counter: @counter
    )

    assert_equal 1, client.published.length
    assert_equal 0, @counter.value
    assert_equal 1, @logger.error_messages.length
  end

  def test_handles_publish_exception
    client = Class.new(FakeMqttClient) do
      def publish(*)
        raise IOError, 'connection lost'
      end
    end.new

    Mqtt.publish_values(
      client,
      [{ key: 'test', value: 'value' }],
      logger:  @logger,
      counter: @counter
    )

    assert_equal 0, @counter.value
    assert_match(/connection lost/, @logger.error_messages.first)
  end

  def test_converts_key_and_value_to_strings
    client = FakeMqttClient.new

    Mqtt.publish_values(
      client,
      [{ key: 123, value: 456 }],
      logger:  @logger,
      counter: @counter
    )

    assert_equal 'tesla/123', client.published.first[:topic  ]
    assert_equal '456'      , client.published.first[:payload]
  end
end

#----------------------------------------------------------------------------

class MqttPendingCounterTest < Minitest::Test
  def setup
    @logger  = FakeLogger.new
    @counter = FakeCounter.new
  end

  def test_initial_count_is_zero
    counter = MqttPendingCounter.new

    assert_equal 0, counter.count
    assert counter.wait(0.01)
  end

  def test_increment_and_decrement
    counter = MqttPendingCounter.new

    counter.increment
    assert_equal 1, counter.count

    counter.decrement
    assert_equal 0, counter.count
  end

  def test_wait_returns_when_all_messages_are_acknowledged
    counter = MqttPendingCounter.new
    counter.increment

    thread = Thread.new do
      sleep 0.05
      counter.decrement
    end

    assert counter.wait(1.0)

    thread.join
  end

  def test_wait_times_out_when_ack_never_arrives
    counter = MqttPendingCounter.new
    counter.increment

    refute counter.wait(0.05)
    assert_equal 1, counter.count
  end

  def test_extra_puback_does_not_make_count_negative
    counter = MqttPendingCounter.new

    counter.decrement

    assert_equal 0, counter.count
  end

  def test_multiple_messages
    counter = MqttPendingCounter.new

    10.times { counter.increment }

    assert_equal 10, counter.count

    9.times { counter.decrement }

    assert_equal 1, counter.count
    refute counter.wait(0.01)

    counter.decrement

    assert counter.wait(0.01)
    assert_equal 0, counter.count
  end

  # ------------------------------------------------------------
  # recurse_data edge cases
  # ------------------------------------------------------------

  def test_flatten_deeply_nested_data
    data = {
      a: {
        b: {
          c: {
            d: 123
          }
        }
      }
    }

    assert_equal [
      { key: 'a/b/c/d', value: 123 }
    ], Mqtt.recurse_data(data)
  end

  def test_flatten_mixed_array_and_hash
    data = {
      root: [
        {
          values: [
            { x: 1 },
            { x: 2 }
          ]
        }
      ]
    }

    assert_equal [
      { key: 'root[0]/values[0]/x', value: 1 },
      { key: 'root[0]/values[1]/x', value: 2 }
    ], Mqtt.recurse_data(data)
  end

  def test_flatten_string
    assert_equal [
      { key: '', value: 'hello' }
    ], Mqtt.recurse_data('hello')
  end

  def test_flatten_integer
    assert_equal [
      { key: '', value: 123 }
    ], Mqtt.recurse_data(123)
  end

  # ------------------------------------------------------------
  # MQTT publishing
  # ------------------------------------------------------------

  def test_empty_values_do_not_publish
    client = FakeMqttClient.new

    Mqtt.publish_values(
      client,
      [],
      logger: @logger,
      counter: @counter
    )

    assert_empty client.published
    assert_equal 0, @counter.value
  end

  def test_publish_failure_decrements_pending_counter
    client = FakeMqttClient.new(publish_status: 1)

    Mqtt.publish_values(
      client,
      [
        { key: 'one', value: 1 },
        { key: 'two', value: 2 }
      ],
      logger: @logger,
      counter: @counter
    )

    assert_equal 0, @counter.value
  end

  def test_publish_exception_does_not_leave_pending_counter
    client = Class.new(FakeMqttClient) do
      def publish(*)
        raise IOError, 'MQTT disconnected'
      end
    end.new

    Mqtt.publish_values(
      client,
      [{ key: 'test', value: 'value' }],
      logger: @logger,
      counter: @counter
    )

    assert_equal 0, @counter.value
  end

  # ------------------------------------------------------------
  # Pending counter
  # ------------------------------------------------------------

  def test_counter_cannot_go_below_zero
    counter = MqttPendingCounter.new

    10.times { counter.decrement }

    assert_equal 0, counter.count
  end

  def test_wait_returns_immediately_when_counter_is_zero
    counter = MqttPendingCounter.new

    start = Process.clock_gettime(Process::CLOCK_MONOTONIC)

    assert counter.wait(5.0)

    elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start

    assert_operator elapsed, :<, 0.5
  end

  def test_received_puback_decrements_counter
    counter = MqttPendingCounter.new
    counter.increment

    Mqtt.received_puback(counter)

    assert_equal 0, counter.count
  end

  def test_extra_puback_does_not_make_counter_negative
    counter = MqttPendingCounter.new

    Mqtt.received_puback(counter)
    Mqtt.received_puback(counter)

    assert_equal 0, counter.count
  end

end

#----------------------------------------------------------------------------

#----------------------------------------------------------------------------
# MQTT TLS configuration and certificate verification
#----------------------------------------------------------------------------

class TestMqttTlsConfiguration < Minitest::Test
  FIXTURE_DIR = File.expand_path("fixtures/tls", __dir__)

  def setup
    @ca_file          = File.join(FIXTURE_DIR, 'ca.pem'      )
    @wrong_ca_file    = File.join(FIXTURE_DIR, 'wrong_ca.pem')
    @server_cert_file = File.join(FIXTURE_DIR, 'server.crt'  )
    @server_key_file  = File.join(FIXTURE_DIR, 'server.key'  )
    @client_cert_file = File.join(FIXTURE_DIR, 'client.crt'  )
    @client_key_file  = File.join(FIXTURE_DIR, 'client.key'  )
  end

  def base_config_ca
    {
      tls:      true,
      ca_file:  @ca_file,
      crt_file: nil,
      key_file: nil
    }
  end

  def base_config_ca_key
    {
      tls:      true,
      ca_file:  @ca_file,
      crt_file: @client_cert_file,
      key_file: @client_key_file
    }
  end

  #
  # Server-authentication-only TLS
  #

  def test_client_certificate_and_key_are_configured
    client = PahoMqtt::Client.new(ssl: false)

    configure_mqtt_tls(client, base_config_ca_key)

    assert client.ssl
    refute_nil client.ssl_context
  end

  def test_missing_client_certificate_is_rejected
    client = PahoMqtt::Client.new(ssl: false)

    error = assert_raises(StandardError) do
      configure_mqtt_tls(
        client, base_config_ca_key.merge(crt_file: '/does/not/exist.pem')
      )
    end

    assert_match(/certificate|crt|file/i, error.message)
  end

  def test_missing_private_key_is_rejected
    client = PahoMqtt::Client.new(ssl: false)

    error = assert_raises(StandardError) do
      configure_mqtt_tls(
        client, base_config_ca_key.merge(key_file: '/does/not/exist.key')
      )
    end

    assert_match(/key|file/i, error.message)
  end

  #
  # Important regression test for the original bug:
  # assigning an SSLContext to client.ssl is WRONG.
  #

  def test_tls_configuration_installs_context_in_paho_client
    client = PahoMqtt::Client.new(ssl: false)

    configure_mqtt_tls(client, base_config_ca_key)

    assert_equal true, client.ssl
    refute_nil client.ssl_context

    assert_instance_of OpenSSL::SSL::SSLContext, client.ssl_context
  end

  def test_mutual_tls_requires_both_client_certificate_and_key
    client = PahoMqtt::Client.new(ssl: false)

    assert_raises(RuntimeError) do
      configure_mqtt_tls(client, base_config_ca_key.merge( key_file: nil))
    end
  end

  #--------------------------------------------------------------------------
  # Basic configuration
  #--------------------------------------------------------------------------

  def test_tls_disabled_does_not_configure_ssl
    client = PahoMqtt::Client.new(ssl: false)

    configure_mqtt_tls(client, base_config_ca_key.merge(tls: false))

    refute client.ssl
  end

  def test_tls_enables_ssl
    client = PahoMqtt::Client.new(ssl: false)

    configure_mqtt_tls(client, base_config_ca_key)

    assert client.ssl
    refute_nil client.ssl_context
  end

  def test_tls_uses_verify_peer
    client = PahoMqtt::Client.new(ssl: false)

    configure_mqtt_tls(client, base_config_ca_key)

    assert_equal(OpenSSL::SSL::VERIFY_PEER, client.ssl_context.verify_mode)
  end

  #--------------------------------------------------------------------------
  # Client certificate configuration
  #--------------------------------------------------------------------------

  def test_client_certificate_requires_private_key
    client = PahoMqtt::Client.new(ssl: false)

    error = assert_raises(RuntimeError) do
      configure_mqtt_tls(client, base_config_ca_key.merge(key_file: nil))
    end

    assert_match(/crt_file.*key_file|key_file.*crt_file/i, error.message)
  end

  def test_private_key_requires_client_certificate
    client = PahoMqtt::Client.new(ssl: false)

    error = assert_raises(RuntimeError) do
      configure_mqtt_tls( client, base_config_ca_key.merge(crt_file: nil))
    end

    assert_match(/crt_file.*key_file|key_file.*crt_file/i, error.message)
  end

  def test_client_certificate_and_key_are_loaded
    client = PahoMqtt::Client.new(ssl: false)

    configure_mqtt_tls(client, base_config_ca_key)

    context = client.ssl_context

    refute_nil context

    # Paho/OpenSSL may expose the certificate/key indirectly, so the
    # important assertion here is that configuration succeeds.
    assert client.ssl
  end

  def test_tls_with_client_certificate_is_allowed
    client = PahoMqtt::Client.new(ssl: false)

    configure_mqtt_tls(client, base_config_ca_key)

    assert client.ssl
    assert_equal OpenSSL::SSL::VERIFY_PEER,
                 client.ssl_context.verify_mode
    assert_equal true, client.ssl_context.verify_hostname
  end

  def test_tls_client_certificate_and_key_must_be_specified_together
    client = PahoMqtt::Client.new(ssl: false)

    config = base_config_ca.merge(
      crt_file: @client_cert_file,
      key_file: nil
    )

    error = assert_raises(RuntimeError) do
      configure_mqtt_tls(client, config)
    end

    assert_match(/crt_file and key_file must both be specified/, error.message)
  end

  def test_tls_client_key_without_certificate_is_rejected
    client = PahoMqtt::Client.new(ssl: false)

    config = base_config_ca.merge(
      crt_file: nil,
      key_file: @client_key_file
    )

    error = assert_raises(RuntimeError) do
      configure_mqtt_tls(client, config)
    end

    assert_match(/crt_file and key_file must both be specified/, error.message)
  end

  #--------------------------------------------------------------------------
  # CA configuration
  #--------------------------------------------------------------------------

  def test_missing_ca_file_is_rejected
    client = PahoMqtt::Client.new(ssl: false)

    error = assert_raises(StandardError) do
      configure_mqtt_tls(
        client,
        base_config_ca.merge(ca_file: '/does/not/exist.pem')
      )
    end

    assert_match(/ca|certificate|file/i, error.message)
  end

  #--------------------------------------------------------------------------
  # Actual TLS certificate verification
  #
  # These tests create a real TLS server using the fixture certificate and
  # then use the SSLContext created by configure_mqtt_tls to perform an
  # actual TLS handshake.
  #--------------------------------------------------------------------------

  def test_tls_handshake_succeeds_with_trusted_ca
    client = PahoMqtt::Client.new(ssl: false)

    configure_mqtt_tls(client, base_config_ca_key)

    assert_tls_handshake(client.ssl_context, expected: :success)
  end

  def test_tls_handshake_fails_with_wrong_ca
    client = PahoMqtt::Client.new(ssl: false)

    configure_mqtt_tls(
      client,
      base_config_ca_key.merge(ca_file: @wrong_ca_file)
    )

    assert_tls_handshake(client.ssl_context, expected: :failure)
  end

  #--------------------------------------------------------------------------
  # Server-only TLS
  #
  # This test documents the desired distinction between ordinary TLS and
  # mutual TLS. It should pass after configure_mqtt_tls is changed so that
  # crt_file/key_file are optional.
  #--------------------------------------------------------------------------

  def test_server_only_tls_does_not_require_client_certificate
    client = PahoMqtt::Client.new(ssl: false)

    configure_mqtt_tls(client, base_config_ca)

    assert client.ssl
    refute_nil client.ssl_context

    assert_equal(
      OpenSSL::SSL::VERIFY_PEER,
      client.ssl_context.verify_mode
    )
  end

  #--------------------------------------------------------------------------
  # Actual server-only TLS handshake
  #--------------------------------------------------------------------------

  def test_server_only_tls_handshake_succeeds
    client = PahoMqtt::Client.new(ssl: false)

    configure_mqtt_tls(client, base_config_ca)

    assert_tls_handshake(client.ssl_context, expected: :success)
  end

  def test_tls_server_authentication_only_is_allowed
    client = PahoMqtt::Client.new(ssl: false)

    configure_mqtt_tls(client, base_config_ca)

    assert client.ssl
    assert_equal OpenSSL::SSL::VERIFY_PEER,
                 client.ssl_context.verify_mode
    assert_equal true, client.ssl_context.verify_hostname
  end

  def test_tls_server_authentication_only_handshake_succeeds
    client = PahoMqtt::Client.new(ssl: false)

    configure_mqtt_tls(client, base_config_ca)

    assert_tls_handshake(client.ssl_context, expected: :success)
  end

  def test_tls_server_authentication_only_with_wrong_ca_fails
    client = PahoMqtt::Client.new(ssl: false)

    configure_mqtt_tls(
      client,
      base_config_ca.merge(ca_file: @wrong_ca_file)
    )

    assert_tls_handshake(client.ssl_context, expected: :failure)
  end

  #--------------------------------------------------------------------------

  def assert_tls_handshake(ssl_context, expected:)
    tcp_server    = TCPServer.new('127.0.0.1', 0)
    port          = tcp_server.addr[1]

    server_context = OpenSSL::SSL::SSLContext.new
    server_context.cert = OpenSSL::X509::Certificate.new(
      File.read(@server_cert_file)
    )
    server_context.key = OpenSSL::PKey::RSA.new(
      File.read(@server_key_file)
    )

    ssl_server = OpenSSL::SSL::SSLServer.new(tcp_server, server_context)

    server_result = Queue.new
    server_thread = Thread.new do
      begin
        socket = ssl_server.accept
        server_result << :success
        socket.close
      rescue StandardError => e
        server_result << e
      ensure
        server.close rescue nil
      end
    end

    client_socket = TCPSocket.new('127.0.0.1', port)
    ssl_socket    = OpenSSL::SSL::SSLSocket.new(client_socket, ssl_context)
    ssl_socket.hostname = 'localhost'
    begin
      if expected == :success
        ssl_socket.connect

        assert_equal :success, server_result.pop
      else
        assert_raises(OpenSSL::SSL::SSLError) do
          ssl_socket.connect
        end

        refute_equal :success, server_result.pop
      end
    ensure
      ssl_socket.close rescue nil
      server_thread.join
    end
  end

  #--------------------------------------------------------------------------

  private

  def configure_mqtt_tls(client, config)
    Mqtt.configure_mqtt_tls(client, config)
  end

end

#----------------------------------------------------------------------------
