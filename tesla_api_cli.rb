#!/usr/bin/ruby -w

# tesla_api_cli
#
# CLI interface for the Tesla Fleet API.
#
# This script allows command line access to the endpoints in the Tesla Fleet
# API.  It does not provide access the Fleet Telemetry streaming  protocol.
#
# A config file (named tesla_api.json) must be created in ../credentials,
# ./config or . (a specified config dir) to provide information needed to
# authenticate and connect to the Fleet API.
#
# In addition to providing direct access to the Fleet API, it also provides
# some convenience functions to maintain the authentication server needed
# to allow connection to the Fleet API:
#
# --register       Register partner ID
# --login-url      Print URL to login with on a web browser
# --login-browser  Initiate login via web browser
#
# The following options are used to provide direct access to the Fleet API:
#
# --list           List available endpoints for the REST API and the signed
#                  message API.
#
# ENDPOINTS        Allows you to specify one or more endpoints to call.
#                  If --post-data or --post-param is specified, requests will
#                  be a POST.  Otherwise, requests will be a GET.
#                  DELETE requests are not supported.
#                  Endpoints may be abbreviated in the following ways:
#                 - Including "/api/1" or not
#                 - Specifying "{vin}" to indicate using a vin specified
#                   in the config file or application command line.
#                 - Omitting "/vehicles/{vin}" as a shorthand to vehicle endpoints.
#                 - Specifying "location_data" as a shorthand for
#                   "vehicle_data?endpoints=location_data".
#                 - Specifying "location_data" (or other vehicle_data
#                   sub-requests) as a shorthand for
#                   "vehicle_data?endpoints=location_data".
#                 - Omitting "?vin={vin}" on endpoints that require it.
#
# --post-data      Allows you to provide JSON data to be posted to the endpoint
#                  that was specified.  Only one endpoint should be specified
#                  if --post-data is used.
#
# --post-param     Shortcut to allow specifying the post data one value at a
#                  time, as opposed to the full JSON payload in --post-data.
#                  For example --post-param='which_trunk:front' translates to
#                  --post-data='{"which_trunk": "front"}'.
#                  Multiple --post-param options may be specified.
#                  Only upper level parameters are supported.
#
# --vehicles       Allows to specify a comma separated list of VINs that will
#                  override what is specified in the config file.  Each endpoint
#                  will be called for each vehicle.
#
# --wake           Wakes the vehicle if it is not already awake (can be used
#                  along with ENDPOINTS) to ensure the vehicle is awake before
#                  requesting data.  Waking a vehicle is a more expensive API
#                  call.
#
# --consolidated   Output consolidated JSON data for multiple endpoints/vehicle
#                  IDs.  This is used for MQTT processing (mainly for vehicle
#                  and location data).  Otherwise, data is returned exactly
#                  as provided by the Tesla Fleet API.  Note that if multiple
#                  endpoints/vehicle IDs are used with the non-consolidated
#                  form, you will get an array of results in most cases.
#
# See Tesla Developer docs for list of endpoints:
#   https://developer.tesla.com/docs/fleet-api/endpoints/vehicle-management
# Endpoints supported by the program are listed in lib/TeslaAPIEndpoints.rb.

require 'bundler/setup'
require 'getoptlong'
require 'logger'
require 'rbconfig'

require_relative 'lib/Config'
require_relative 'lib/TeslaAPI'

#----------------------------------------------------------------------------

$prog = File.basename($0).sub(/\.rb$/, '')

list               = false
config_file_name   = 'tesla_api.json'
config_dir         = nil
register           = false
login_url          = false
login_browser      = false
wake               = false
consolidated       = false
vins_or_ids        = nil
post_data          = nil
post_params        = []
endpoints          = nil
verbose            = false
debug              = false

usage = <<-EOF
#{$prog} [OPTIONS] [ENDPOINTS]

Options:
-l  --list           List available endpoints
    --config-dir=    Location of config files
    --register       Register partner ID (only needs to be done once)
-u, --login-url      Print URL to login with on a web browser
-b, --login-browser  Initiate login via web browser
-V, --vehicles=vin   Specify vehicle(s) to query (from config if blank)
-w, --wake           Ensure vehicle is awake
-c, --consolidated   Output consolidated data from Tesla Fleet API
-d, --post-data      JSON data for Tesla API POST
-p, --post-param     A single post parameter to build the post data JSON
-v, --verbose        Print verbose output
-x, --debug          Print debug output
-h, --help           Print help message
EOF

begin
  opts = GetoptLong.new(
    [ '--list'         , '-l', GetoptLong::NO_ARGUMENT       ],
    [ '--config-dir'         , GetoptLong::REQUIRED_ARGUMENT ],
    [ '--register'           , GetoptLong::NO_ARGUMENT       ],
    [ '--login-url'    , '-u', GetoptLong::NO_ARGUMENT       ],
    [ '--login-browser', '-b', GetoptLong::NO_ARGUMENT       ],
    [ '--vehicles'     , '-V', GetoptLong::REQUIRED_ARGUMENT ],
    [ '--wake'         , '-w', GetoptLong::NO_ARGUMENT       ],
    [ '--consolidated' , '-c', GetoptLong::NO_ARGUMENT       ],
    [ '--post-data'    , '-d', GetoptLong::REQUIRED_ARGUMENT ],
    [ '--post-param'   , '-p', GetoptLong::REQUIRED_ARGUMENT ],
    [ '--verbose'      , '-v', GetoptLong::NO_ARGUMENT       ],
    [ '--debug'        , '-x', GetoptLong::NO_ARGUMENT       ],
    [ '--help'         , '-h', GetoptLong::NO_ARGUMENT       ],
  )

  opts.each do |opt, arg|
    case opt
    when '--list'           then list           = true
    when '--config-dir'     then config_dir     = arg
    when '--register'       then register       = true
    when '--login-url'      then login_url      = true
    when '--login-browser'  then login_browser  = true
    when '--wake'           then wake           = true
    when '--consolidated'   then consolidated   = true
    when '--vehicles'       then vins_or_ids    = arg
    when '--post-data'      then post_data      = arg
    when '--post-param'     then post_params   << arg
    when '--verbose'        then verbose        = true
    when '--debug'          then debug          = true
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

unless post_data.nil? || post_params.empty?
  abort "#{$prog}: cannot specify both post_data and post_param"
end

#----------------------------------------------------------------------------

def safe_cli_error_message(error)
  message = error.message.to_s

  # Remove terminal control sequences before displaying an
  # exception originating from user/network supplied data.
  message
    .gsub(/\e\[[0-?]*[ -\/]*[@-~]/, '')
    .gsub(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/, '')
end

#----------------------------------------------------------------------------

# Configure a logger.
logger = Logger.new(STDERR)
logger.level = debug ? Logger::DEBUG
                      : (verbose ? Logger::INFO : Logger::WARN)

begin
  tesla_api = TeslaAPI.new(config_dir, config_file_name, logger: logger)
rescue RuntimeError => e
  abort "#{$prog}: #{e.message}"
end

vins_or_ids = tesla_api.config[:vin] if vins_or_ids.nil? || vins_or_ids.empty?

#----------------------------------------------------------------------------

if list
  puts "REST API endpoints:\n\n"
  puts TeslaAPI::list_commands.join("\n")
  puts "\nVehicle commands:\n\n"
  puts Tesla::VehicleCommand.list_commands.join("\n")
  puts "\nCar Service commands:\n\n"
  puts Tesla::CarServerCommand.list_commands.join("\n")
end

#----------------------------------------------------------------------------

puts tesla_api.register_account if register

#----------------------------------------------------------------------------

if login_url || login_browser
  url = "https://#{tesla_api.config[:public_host]}/auth/start"

  if login_url
    puts url
  else
    logger.info url
  end

  if login_browser
    cmd = case RbConfig::CONFIG['host_os']
          when /mswin|mingw|cygwin/ then 'start'
          when /darwin/             then 'open'
          when /linux|bsd/          then 'xdg-open'
          else raise "Unsupported operating system"
          end
    system cmd, url
  end
end

#----------------------------------------------------------------------------

# Wake up the vehicle.  Wake calls are comparatively expensive for the Tesla
# Fleet API.  So, only wake the vehicle up if it is not online.
if wake
  vins_or_ids&.split(/,/).each do |id_or_vin|
    unless tesla_api.get_vehicle_state(id_or_vin) == 'online'
      tesla_api.wake_up_vehicle(id_or_vin)

      # Try to wait until the vehicle wakes up.
      5.times do
        sleep 2
        break if tesla_api.get_vehicle_state(id_or_vin) == 'online'
      end
    end
  end
end

#----------------------------------------------------------------------------

if post_data.nil?
  post_data_hash = nil
else
  begin
    post_data_hash = JSON.parse(post_data, symbolize_names: true)
  rescue JSON::ParserError => e
    logger.fatal "Invalid post data (#{safe_cli_error_message(e)})"
    exit 1
  end
  unless post_data_hash.is_a?(Hash)
    logger.fatal '--post-data must contain a JSON object'
    exit 1
  end
end

# Build post_data out post_params if provided.
unless post_params.nil? || post_params.empty?
  post_data_hash ||= {}
  post_params.each do |post_param|
    match = post_param.match(/\A([^:]+):(.*)\z/)
    if match
      key, value = match.captures
      value = case value
              when /\A-?\d+\z/
                value.to_i
              when /\A-?\d+(?:\.\d+)?\z/
                value.to_f
              else
                value
              end
      post_data_hash[key] = value
    else
      logger.fatal "Invalid post param \"#{post_param}\""
      exit 1
    end
  end
end

begin
  data = tesla_api.process_endpoints(endpoints, vins_or_ids, post_data_hash, consolidated)
  puts data unless data.nil? || data.empty?
rescue RuntimeError => e
  logger.fatal safe_cli_error_message(e)
  exit 1
end

#----------------------------------------------------------------------------
