#!/usr/bin/ruby -w

# tesla_api_server
#
# Server that integrates with the Tesla Fleet API.
#
# Provides the following:
# - Endpoint for providing a public key
# - Endpoints for handling OAuth2 requests
# - Endpoint to allow user login

# Derived from
#   https://github.com/qcteslaguy/tesla-fleet-api-demo/blob/main/tesla_oauth_demo.py

require 'bundler/setup'
require 'sinatra'
require 'json'
require 'cgi'
require 'getoptlong'
require 'logger'

require_relative 'lib/Config'
require_relative 'lib/TeslaAPI'

#----------------------------------------------------------------------------

$prog = File.basename($0).sub(/\.rb$/, '')

config_file_name = 'tesla_api.json'
config_dir       = nil
verbose          = false
debug            = false

# Sinatra wants to look at the arguments first.  So, our options have to
# be after '--'.  However, at this point, ARGV still has the Sinatra options.
# We can strip them off at this point.
dash_dash_index = ARGV.index('--')
if dash_dash_index
  ARGV.shift(dash_dash_index + 1) # Remove Sinatra arguments before --
else
  ARGV.shift(ARGV.size)           # Remove all Sinatra arguments
end

usage = <<-EOF
#{$prog} [SINATRA_OPTIONS] [-- [OPTIONS]]

OPTIONS:
-c, --config-dir=  Alternate location of config files
-v, --verbose      Print verbose output
-x, --debug        Print debug output
-h, --help         Print help message

SINATRA_OPTIONS:
-e, --environment= production/development
EOF

begin
  opts = GetoptLong.new(
    [ '--config-dir', '-c', GetoptLong::REQUIRED_ARGUMENT ],
    [ '--verbose'   , '-v', GetoptLong::NO_ARGUMENT       ],
    [ '--debug'     , '-x', GetoptLong::NO_ARGUMENT       ],
    [ '--help'      , '-h', GetoptLong::NO_ARGUMENT       ],
  )

  opts.each do |opt, arg|
    case opt
    when '--config-dir'  then config_dir = arg
    when '--verbose'     then verbose    = true
    when '--debug'       then debug      = true
    when '--help'
      puts usage
      exit 0
    end
  end
rescue GetoptLong::InvalidOption
  # Already reported, no need for stack trace
  exit 1
end

abort "#{$prog}: unexpected arguments\n#{usage}" if ARGV.length > 0

#----------------------------------------------------------------------------

# Configure a logger.
logger = Logger.new(STDERR)
logger.level = debug ? Logger::DEBUG
                      : (verbose ? Logger::INFO : Logger::WARN)

# Need to allow Tesla servers to access the production application.
configure :production do
  disable :logging
  set :host_authorization, {
    permitted_hosts: []
  }
end

configure :development do
  set :host_authorization, {
    permitted_hosts: []
  }
end

begin
  tesla_api = TeslaAPI.new(config_dir, config_file_name, logger: logger)
  set :tesla_api, tesla_api
rescue RuntimeError => e
  abort "#{$prog}: #{e.message}"
end

configure do
  # Setup the web server environment.  Use values from config file instead of
  # the Sinatra default or Sinatra command line options.
  set :port, tesla_api.config[:local_port     ]
  set :bind, tesla_api.config[:local_interface]

  set :sessions,
      key:          'tesla.oauth.session',
      httponly:     true,
      secure:       !(development? || test?), # false allows unit tests to work
      same_site:    :lax,
      expire_after: 10 * 60

  set :session_secret, tesla_api.config[:session_secret]
end

#----------------------------------------------------------------------------

helpers do
  #--------------------

  # Render a message (instead of vehicle data) in HTML or JSON.
  #
  # @param emit_json [Boolean] Emit JSON as opposed to HTML
  # @param html_tag  [String]  HTML tag to wrap around message
  # @param message   [String]  Message to emit
  # @param id        [String]  ID of vehicle to include in message (default nil)
  # @return [String] Generated message string

  def generate_message(emit_json, html_tag, message, id=nil)
    if emit_json
      content_type :json
      if id.nil?
        { error: message }.to_json
      else
        { vehicles: { id => { communication_status: message } } }.to_json
      end
    else
      content_type :html
      "<#{html_tag}>Status: #{CGI.escapeHTML(message)}</#{html_tag}>"
    end
  end

  #--------------------
end

#----------------------------------------------------------------------------

# Only allow the public key to be publically accessible.  All other endpoints
# will be limited to the public host.
before do
  next if request.path == '/.well-known/appspecific/com.tesla.3p.public-key.pem'

  # Uncomment the following if you only want to allow access to the sign-in
  # endpoints from your public host.  This precludes being able to access the
  # endpoint via your local network (i.e. http://INTERNAL_HOST_NAME:8089).
  # If you are using ngrok, a similar ability exists in the ngrok traffic
  # policy file (which will not interfere with local network access).
=begin
  expected_host = settings.tesla_api.config[:public_host]
  unless request.host == expected_host
    halt 403, 'Invalid Host header'
  end
=end
end

#----------------------------------------------------------------------------

# Endpont for getting the public key that the Tesla API needs.
# This endpoint must be public for any host to access.
get '/.well-known/appspecific/com.tesla.3p.public-key.pem' do
  send_file("#{__dir__}/.well-known/appspecific/com.tesla.3p.public-key.pem")
end

#----------------------------------------------------------------------------

# Endpoint to start the Tesla authentication process.
get '/auth/start' do
  authorize_state = SecureRandom.urlsafe_base64(32)
  session[:authorize_state] = authorize_state
  redirect settings.tesla_api.generate_login_url(authorize_state)
end

#----------------------------------------------------------------------------

# Auth callback.
get '/auth/callback' do
  logger.debug 'OAuth callback received'

  authorize_state = session[:authorize_state]
  provided_state  = params['state']

  unless    authorize_state \
         && provided_state  \
         && Rack::Utils.secure_compare(provided_state, authorize_state)

    logger.debug 'OAuth state invalid'
    halt 400, generate_message(false, 'pre', 'Invalid state parameter (possible CSRF)')
  end

  session.delete(:authorize_state)

  if params['error']
    logger.debug 'OAuth authorization failed'
    halt 400, generate_message(false, 'h2',
                               'Unable to complete Tesla authentication')
  end

  logger.debug 'OAuth state valid'

  code = params['code']

  unless code && !code.empty?
    halt 400, generate_message(false, 'pre', "Missing authorization code")
  end

  begin
    response_code, _data = settings.tesla_api.exchange_authorization_code(code)
  rescue StandardError => e
    logger.debug "OAuth callback failed: #{e.class}"

    halt 500, generate_message(false, 'pre',
                               'Unable to complete Tesla authentication')
  end
  if response_code == 403
    halt 403, generate_message(false, 'h2', 'Incorrect user for application')
  elsif response_code != 200
    halt 400, generate_message(false, 'pre', "Token exchange failed (#{response_code})")
  end

  logger.debug 'OAuth code valid'

  redirect '/'
end

#----------------------------------------------------------------------------

# Endpoint to allow logging in and confirming the user is logged in.
get '/' do
  html = ''

  if !settings.tesla_api.have_access_token?
    html = <<~HTML
      <h1>Tesla Fleet API</h1>
      <a href=/auth/start>Login with Tesla</a>
    HTML
  else
    html = '<h2>Successfully logged in</h2>'
  end

  html
end

#----------------------------------------------------------------------------
