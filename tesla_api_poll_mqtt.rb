#!/usr/bin/ruby
# Note: the paho-mqtt gem generates warnings (so no "-w" on the #! line)

# tesla_api_poll_mqtt
#
# Program to poll for vehicle data and location data from the Tesla Fleet API
# and publish that data to MQTT.  The data is only polled once.  It is up to
# a calling program to run this program periodically.

require 'bundler/setup'
require 'paho-mqtt'
require 'json'
require 'getoptlong'
require 'logger'
require 'shellwords'
require 'open3'
require 'timeout'
require 'openssl'

require_relative 'lib/Config'
require_relative 'lib/Mqtt'
include Mqtt

#----------------------------------------------------------------------------

$prog = File.basename($0).sub(/\.rb$/, '')

cli_script = "#{__dir__}/bin/cli"

# default_endpoint = [ 'location_data', 'vehicle_data' ]
# endpoints below is the same as 'location_data vehicle_data' but only makes
# one API call.
# Could drop some of these if they aren't interesting (such as gui_settings
# or vehicle_config).

default_endpoint = 'vehicle_data?endpoints=charge_state;climate_state;closures_state;drive_state;gui_settings;location_data;vehicle_config;vehicle_state'

endpoints        = [ default_endpoint ]
config_file_name = 'mqtt.json'
config_dir       = nil
wake             = false
verbose          = false
debug            = false

usage = <<-EOF
#{$prog} [OPTIONS] [ENDPOINTS]

Options:
-c, --config-dir=  Location of config files
-w, --wake         Ensure vehicle is awake
-v, --verbose      Print verbose output
-x, --debug        Print debug output
-h, --help         Print help message
EOF

begin
  opts = GetoptLong.new(
    [ '--config-dir', '-c', GetoptLong::REQUIRED_ARGUMENT ],
    [ '--wake'      , '-w', GetoptLong::NO_ARGUMENT       ],
    [ '--verbose'   , '-v', GetoptLong::NO_ARGUMENT       ],
    [ '--debug'     , '-x', GetoptLong::NO_ARGUMENT       ],
    [ '--help'      , '-h', GetoptLong::NO_ARGUMENT       ],
  )

  opts.each do |opt, arg|
    case opt
    when '--config-dir' then config_dir = arg
    when '--wake'       then wake       = true
    when '--verbose'    then verbose    = true
    when '--debug'      then debug      = true
    when '--help'
      puts usage
      exit 0
    end
  end
rescue GetoptLong::InvalidOption
  # Already reported, no need for stack trace
  exit 1
end

endpoints = ARGV if ARGV.length > 0

#----------------------------------------------------------------------------

# Configure a logger.
$logger = Logger.new(STDERR)
$logger.level = debug ? Logger::DEBUG
                      : (verbose ? Logger::INFO : Logger::WARN)

# PahoMqtt will only take a file name for a logger and it might not
# like stderr if this script is being called by something that doesn't
# have stderr open.  Just let it do it's default action in that case
# (it seems to work as needed).
begin
  PahoMqtt::logger = '/dev/stderr'
  PahoMqtt::logger.level = $logger.level
rescue Errno::ENXIO
  # stderr not connected to a device, just log to default
end

#----------------------------------------------------------------------------

# Read configuration file.
config = Config.read_json(config_file_name, config_dir)

config[:host      ] ||= '127.0.0.1'
config[:port      ] ||= config[:tls] ? 8883 : 1883
config[:keep_alive] ||= 15
config[:tls       ] ||= false
config[:client_id ] ||= "tesla_api_ruby_bridge_#{$$}"

# Strict IPv4 Regex (Matches 0.0.0.0 through 255.255.255.255)
ip_regexp = /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/
# Hostname Regex (Matches valid DNS labels up to 63 chars, separated by dots)
hostname_regexp = /(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?/

validations = [
  { setting: :host      , pattern: /\A(?:#{ip_regexp}|#{hostname_regexp})\z/   },
  { setting: :port      , pattern: /\A\d{1,5}\z/     , range: (1..65535)       },
  { setting: :keep_alive, pattern: /\A\d+\z/                                   },
  { setting: :tls       , pattern: /^(true|false)$/                            },
  { setting: :client_id , pattern: /\A[[:graph:]]+\z/                          },
  { setting: :username  , pattern: /\A[[:graph:]]*\z/, optional: true          },
  { setting: :password  , pattern: /\A[[:graph:]]*\z/, optional: true          },
  { setting: :key_file  , file_exists: true          , optional: true          },
  { setting: :crt_file  , file_exists: true          , optional: true          },
  { setting: :ca_file   , file_exists: true          , optional: !config[:tls] },
]

validations.each do |validation|
  setting     = validation[:setting    ]
  pattern     = validation[:pattern    ]
  range       = validation[:range      ]
  optional    = validation[:optional   ]
  file_exists = validation[:file_exists]
  value       = config[setting].to_s

  next if optional && value.empty?

  if !pattern.nil? && value !~ pattern
    abort "#{$prog}: Invalid configuration value for #{setting}"
  end
  if !range.nil? && !range.cover?(value.to_i)
    abort "#{$prog}: Invalid value for #{setting} (#{range})"
  end
  if !value.empty? && !file_exists.nil? && !File.exist?(value)
    abort "#{$prog}: No such file for #{setting} (#{value})"
  end
end

# Make sure non-strings are the correct type.
config[:tls       ] = config[:tls       ].to_s == 'true'
config[:keep_alive] = config[:keep_alive].to_i

#----------------------------------------------------------------------------

# Build the command to generate vehicle data.
cmd = [cli_script, '--consolidated', *endpoints]
cmd << '--wake' if wake
#$logger.debug "cmd = #{cmd.inspect}"

# Run the command and take the received vehicle data and publish it via MQTT.
stdout, status = Open3.capture2(*cmd)
exit 1 unless status.success?

raw_data = stdout&.strip
$logger.debug "received #{raw_data.to_s.bytesize} bytes of vehicle data"
begin
  data = JSON.parse(raw_data, symbolize_names: true)
rescue JSON::ParserError
  $logger.fatal "Unable to parse request results"
  exit 1
end
if data.is_a?(Hash)
  $logger.debug "vehicle data fields: #{data.keys.map(&:to_s).sort.join(', ')}"
else
  $logger.debug "vehicle data type: #{data.class}"
end

# Open the connection to the MQTT server.
client = nil
begin
  client = PahoMqtt::Client.new(host:            config[:host      ],
                                port:            config[:port      ],
                                client_id:       config[:client_id ],
                                keep_alive:      config[:keep_alive],
                                reconnect_limit: 0,
                                persistent:      false,
                                ssl:             config[:tls],
                               )
rescue PahoMqtt::Exception, SocketError, Timeout::Error => e
  $logger.fatal "Unable to connect to MQTT server (#{e.inspect})"
  exit 1
end

begin
  configure_mqtt_tls(client, config)
rescue RuntimeError => e
  abort "#{$prog}: #{e.message}"
end

counter = MqttPendingCounter.new

client.on_puback { received_puback(counter) }

begin
  client.connect
rescue PahoMqtt::Exception => e
  $logger.fatal "Unable to connect to MQTT server (#{e.message})"
  exit 1
end

# Parse and flatten out the incoming JSON data and publish to MQTT.
publish_values(client, recurse_data(data), logger: $logger, counter: counter) unless data.nil?

# Make sure all of the published values get sent before disconnecting.
# If the timeout is reached (unlikely), then we may drop some messages.
unless counter.wait(20)
  $logger.warn "Timed out waiting for #{counter.count} MQTT PUBACK(s)"
end

client.disconnect

#----------------------------------------------------------------------------
