# frozen_string_literal: true

#----------------------------------------------------------------------------

# Class to safely manage a counter.

class MqttPendingCounter
  def initialize
    @mutex     = Mutex.new
    @condition = ConditionVariable.new
    @count     = 0
  end

  # Increment counter.

  def increment
    @mutex.synchronize { @count += 1 }
  end

  # Decrement counter.

  def decrement
    @mutex.synchronize do
      @count -= 1 if @count > 0
      @condition.broadcast
    end
  end

  # Wait until all publishes succeed or timeout occurs.
  # @param  timeout [Integer] Timeout in seconds
  # @return [Boolean] true if all publishes complete, false if timeout occurred

  def wait(timeout)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout

    @mutex.synchronize do
      while @count > 0
        remaining = deadline -
                    Process.clock_gettime(Process::CLOCK_MONOTONIC)

        break if remaining <= 0

        @condition.wait(@mutex, remaining)
      end

      @count.zero?
    end
  end

  # Provide count of unacknowledged publishes.
  # @return [Integer] Remaining count

  def count
    @mutex.synchronize { @count }
  end
end

#----------------------------------------------------------------------------

# Class to handle publishing data to MQTT.

module Mqtt
  module_function

  #--------------------

  def configure_mqtt_tls(client, config)
    username = config[:username].to_s
    password = config[:password].to_s
    #!!if (!username.empty? || !password.empty?) && !config[:tls]
    #!!  raise RuntimeError, 'TLS is required when MQTT credentials are configured'
    #!!end
    client.username = username unless username.empty?
    client.password = password unless password.empty?

    #!! NOTE: SSL/TLS not tested.
    if config[:tls]
      ca_file  = config[:ca_file ]
      crt_file = config[:crt_file]
      key_file = config[:key_file]

      has_ca  = !ca_file .to_s.empty?
      has_crt = !crt_file.to_s.empty?
      has_key = !key_file.to_s.empty?

      unless has_ca || (has_crt && has_key)
        raise RuntimeError, 'Must supply ca file or key and crt files to use TLS'
      end

      if has_ca && !File.exist?(ca_file)
        raise RuntimeError, 'ca file does not exist'
      end

      unless has_crt == has_key
        raise RuntimeError, 'crt_file and key_file must both be specified or not'
      end

      if has_crt && !File.exist?(crt_file)
        raise RuntimeError, 'crt file does not exist'
      end

      if has_key && !File.exist?(key_file)
        raise RuntimeError, 'key file does not exist'
      end

      client.ssl = true
      client.config_ssl_context(config[:crt_file],
                                config[:key_file],
                                config[:ca_file ])

      client.ssl_context.verify_mode     = OpenSSL::SSL::VERIFY_PEER
      client.ssl_context.verify_hostname = true
    else
      client.ssl = false
    end
  end

  #--------------------

  # Recurse that has we received from the cli script and return a flattened
  # out hash of key/value pairs (and nested arrays) to send via MQTT.
  #
  # @param data     [Hash]   Nested data to derive messages from
  # @param base     [String] Used for recursion to build key for nested values
  # @param messages [Array]  Messages to date
  # @return [Array] Messages

  def recurse_data(data, base = '', messages = [])
    case data
    when Hash
      data.each do |key, value|
        child_base = "#{base}#{base.empty? ? '' : '/'}#{key}"
        recurse_data(value, child_base, messages)
      end
    when Array
      data.each_with_index do |element, index|
        child_base = "#{base}[#{index}]"
        recurse_data(element, child_base, messages)
      end
    else
      messages << { key: base, value: data }
    end

    messages
  end

  #--------------------

  # Publish the key/value pairs to MQTT.
  #
  # @param client [PahoMqtt::Client] MQTT client
  # @param values [Array]            Array of values to publish

  def publish_values(client, values, logger:, counter:)
    values.each do |message|
      key   = message[:key].to_s
      value = message[:value].to_s

      queue_topic     = "tesla/#{key}"
      message_payload = value
      qos = 1 # Ensure message gets delivered at least once

      unless client.connected?
        logger.error "MQTT publish failed for #{queue_topic}: not connected"
        next
      end

      counter.increment

      begin
        status = client.publish(queue_topic, message_payload, false, qos)

        unless status&.zero?
          counter.decrement
          logger.error "MQTT publish failed for #{queue_topic}: status #{status}"
        end
      rescue StandardError => e
        counter.decrement
        logger.error "MQTT publish failed for #{queue_topic}: #{e.message}"
      end
    end
  end

  #--------------------

  # Call from on_puback event when a publish is acknowledged.

  def received_puback(counter)
    counter.decrement
  end

  #--------------------

end

#----------------------------------------------------------------------------
