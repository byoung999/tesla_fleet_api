require 'uri'
require 'securerandom'
require 'json'
require 'deep_merge'
require 'fileutils'
require 'tempfile'
require 'resolv'
require 'rack'

require_relative 'Config'
require_relative 'Https'
require_relative 'TeslaAPIEndpoints'
require_relative 'signed_command/vehicle_command'
require_relative 'signed_command/car_server_command'

#----------------------------------------------------------------------------

# Class to manage all of the communication between applications and the
# Tesla Fleet API.  It does not handle the streaming Fleet Telemetry
# provided by Tesla.

class TeslaAPI
  attr_reader :config

  #--------------------

  # List supported commands.
  #
  # @return [Array] Array of supported commands

  def self.list_commands
    commands = []

    ENDPOINTS.each do |endpoint|
      ep = endpoint[:endpoint]
      command = ep.sub(/^vehicles\/{vin}\//, '') # Use shortcut
      command += ' --post-data={...}' unless endpoint[:verb] == :GET
      commands << command
    end

    VEHICLE_DATA_ENDPOINTS.each do |endpoint|
      commands << endpoint
    end

    commands
  end

  #--------------------

  # Read the configuration file and fill in defaults for any optional items
  # not specifically configured.
  #
  # @param  config_dir [String] Configuration file directory
  # @param  config_file_name [String] Configuration file basename
  # @raise [RuntimeError] If can't read or parse configuration file

  def read_config(config_dir, config_file_name)
    # Read configuration file.
    @config = Config.read_json(config_file_name, config_dir)

    # Required config parameters from config file.
    #   public_host
    #   client_id
    #   client_secret
    [:public_host, :client_id, :client_secret].each do |setting|
      if @config[setting].nil? || @config[setting].empty?
        raise "Config setting #{setting} missing"
      end
    end
  end

  #--------------------

  # Set up an instance of the class, read the configuration and read the
  # last saved access token information.
  #
  # @param  config_dir [String] Configuration file directory
  # @param  config_file_name [String] Configuration file basename
  # @raise [RuntimeError] if can't read or parse configuration or token file

  def initialize(config_dir, config_file_name, logger: nil)
    @logger = logger

    read_config(config_dir, config_file_name)
    augment_config
    validate_config

    # Save the access token to a file, when we get it.  If this process gets
    # restarted, we can read the token from the file instead of requiring the
    # user to login again.
    @access_token_file = File.join(@config[:state_dir], 'tesla_access_token.json')

    @token_mutex   = Mutex.new
    @command_mutex = Mutex.new

    # See if we have tokens from a previous run of this program.
    run_in_token_mutex do
      @tokens = {}
      if File.exist?(@access_token_file)
        mode = File.stat(@access_token_file).mode & 0777
        unless (mode | @config[:state_file_perms]) == @config[:state_file_perms]
          raise "Token file permissions are too permissive (#{mode.to_s(8)})"
        end

        mode = File.stat(@config[:state_dir]).mode & 0777
        unless (mode | @config[:state_dir_perms]) == @config[:state_dir_perms]
          raise "State directory permissions are too permissive " \
                "(#{mode.to_s(8)})"
        end

        begin
          @tokens = JSON.parse(File.read(@access_token_file),
                               symbolize_names: true)
        rescue JSON::ParserError, SystemCallError => e
          raise "Unable to read or parse token file (#{e.message})"
        end

        # First, see if the token file looks properly formatted.
        unless @tokens&.is_a?(Hash) && (@tokens.empty? || token_state != :invalid)
          raise "Invalid token file (#{@access_token_file})"
        end
      end
    end
  end

  #--------------------

  # Augment the configuration with defaults

  def augment_config
    # Optional parameters parameters from config file.
    @config[:local_interface ] ||= '127.0.0.1'
    @config[:local_port      ] ||= 8089
    @config[:redirect_path   ] ||= '/auth/callback'
    @config[:scopes          ] ||= 'openid offline_access user_data vehicle_device_data vehicle_location vehicle_cmds vehicle_specs'
    @config[:auth_host       ] ||= 'fleet-auth.prd.vn.cloud.tesla.com'
    @config[:api_host        ] ||= 'fleet-api.prd.na.vn.cloud.tesla.com'
    @config[:vin             ] ||= nil # Optional, no default
    @config[:tesla_email     ] ||= nil # Optional, no default
    @config[:session_secret  ] ||= nil # Required, no default
    @config[:state_dir       ] ||= "#{__dir__}/../state" # __dir__ is our lib dir
    @config[:state_dir_perms ] ||= 0700
    @config[:state_file_perms] ||= 0600

    @config[:state_dir_perms ] = parse_perms(@config[:state_dir_perms ])
    @config[:state_file_perms] = parse_perms(@config[:state_file_perms])

    @config[:state_dir       ] = File.expand_path(@config[:state_dir])
    @config[:redirect_uri    ] = "https://#{@config[:public_host]}#{@config[:redirect_path]}"
    @config[:local_port      ] = @config[:local_port].to_i
  end

  #--------------------

  # Validate the config setting's basic format.
  #
  # @param   config [Hash] Hash of configuration values (defaults to @config)
  # @return [NilClass] nil
  # @raise  [RuntimeError] If configuration has errors

  def validate_config(config=@config)
    # Strict IPv4 Regex (Matches 0.0.0.0 through 255.255.255.255)
    ip_regexp = /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/
    # Hostname Regex (Matches valid DNS labels up to 63 chars, separated by dots)
    hostname_regexp = /(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?/

    validations = [
      { setting: :public_host     , pattern: /\A(?:#{ip_regexp}|#{hostname_regexp})\z/ },
      { setting: :client_id       , pattern: /\A[\w-]+\z/ },
      { setting: :client_secret   , pattern: /\A[[:graph:]]+\z/ },
      { setting: :local_interface , pattern: Regexp.union(Resolv::IPv4::Regex, Resolv::IPv6::Regex) },
      { setting: :local_port      , pattern: /\A\d{1,5}\z/, range: (1..65535) },
      { setting: :redirect_path   , pattern: /\A\/[^\s?#]+\z/ },
      { setting: :scopes          , pattern: /\A\w+(?: \w+)*\z/ },
      { setting: :auth_host       , pattern: /\Afleet-auth\.prd\.vn\.cloud\.tesla\.com\z/ },
      { setting: :api_host        , pattern: /\A(fleet-api\.prd\.na\.vn\.cloud\.tesla\.com|fleet-api\.prd\.eu\.vn\.cloud\.tesla\.com|fleet-api\.prd\.cn\.vn\.cloud\.tesla\.cn)\z/ },
      { setting: :vehicle_id      , pattern: /\A[A-Z0-9,]*\z/, optional: true },
      { setting: :tesla_email     , pattern: /\A[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}\z/ , optional: true},
      { setting: :session_secret  , pattern: /\A[0-9a-f]{64,}\z/ },
      { setting: :state_dir       , pattern: /\A(?:[a-zA-Z]:\\|[\\\/])?(?:[^\\\/<>:"|?*]+[\\\/])*[^\\\/<>:"|?*]+\z/ },
      { setting: :state_dir_perms , pattern: /\A\d+\z/, range: (0..03777) },
      { setting: :state_file_perms, pattern: /\A\d+\z/, range: (0..03777) },
    ]

    validations.each do |validation|
      setting  = validation[:setting ]
      pattern  = validation[:pattern ]
      range    = validation[:range   ]
      optional = validation[:optional]
      value    = config[setting].to_s

      next if optional && value.empty?

      unless value =~ pattern
        raise "Invalid configuration value for #{setting}"
      end
      if !range.nil? && !range.cover?(value.to_i)
        raise "Invalid value for #{setting} (#{range})"
      end
    end

    nil
  end

  #--------------------

  # Parse an permissions value.  Integers go as is.  Strings are converted
  # to integers handling octal numbers beginning with a zero.
  #
  # @param   perms [String, Integer] Permissions to convert to integer
  # @return [Integer] Parsed permissions

  def parse_perms(perms)
    case perms
    when String # Octal has to be quoted
      if perms =~ /^\d+$/
        perms = perms.to_i((perms =~ /^0/) ? 8 : 10)
      else
        raise "Invalid perms configuration (#{perms})"
      end
    when Integer
      perms = perms.to_i # Decimal, not octal
    else
      raise "Invalid perms configuration (#{perms})"
    end
    perms
  end

  #--------------------

  # Do we have an access token available?
  #
  # @return [Boolean] Whether access token is valid

  def have_access_token?
    @tokens[:access_token].to_s =~ /\A\s*\z/ ? false : true
  end

  #--------------------

  # Are our current tokens valid (not expired)?
  #
  # @return [Symbol] :valid, :invalid, :expired

  def token_state
    return :invalid if @tokens.empty?
    return :invalid unless @tokens&.is_a?(Hash)
    return :invalid if    @tokens[:access_token].to_s.empty? \
                       || @tokens[:obtained_at ].to_s.empty? \
                       || @tokens[:expires_in  ].to_s.empty?

    obtained_at = Integer(@tokens[:obtained_at], exception: false)
    expires_in  = Integer(@tokens[:expires_in ], exception: false)

    return :invalid unless obtained_at && expires_in
    return :invalid unless obtained_at <= Time.now.to_i + 10
    return :invalid unless expires_in > 0

    Time.now.to_i < obtained_at + expires_in - 60 ? :valid : :expired
  end

  #--------------------

  # Take whatever shorthand version of a Tesla Fleet API path and convert
  # it to a full API URL.
  #
  # @param   path [String] Path to expand
  # @return [String] Expanded path

  def expand_api_path(path)
    new_path = case path
               when /\Ahttps:\/\/.+#{Regexp.escape(API_BASE_PATH)}\/(.+)\z/
                 "#{API_BASE_PATH}/#{$1}"
               when /\A#{Regexp.escape(API_BASE_PATH)}/
                 path
               when /\A\//
                 "#{API_BASE_PATH}#{path}"
               else
                 "#{API_BASE_PATH}/#{path}"
               end

    "https://#{@config[:api_host]}#{new_path}"
  end

  #--------------------

  # Take whatever shorthand version of a Tesla Fleet API auth path and
  # convert it to a full API auth URL.
  #
  # @param   path [String] Path to expand
  # @return [String] Expanded path

  def expand_auth_path(path)
    new_path = case path
               when /\Ahttps:\/\/.+#{Regexp.escape(AUTH_BASE_PATH)}\/(.+)\z/
                 "#{AUTH_BASE_PATH}/#{$1}"
               when /^#{Regexp.escape(AUTH_BASE_PATH)}/
                 path
               when /^\//
                 "#{AUTH_BASE_PATH}#{path}"
               else
                 "#{AUTH_BASE_PATH}/#{path}"
               end

    "https://#{@config[:auth_host]}#{new_path}"
  end

  #--------------------

  # Make an endpoint request to the Tesla Fleet API.
  # Returns response code and symbolized hash with response data.
  #
  # @param  verb      [Symbol]  :GET or :POST
  # @param  path      [String]  Path for request (possibly abbreviated)
  # @param  post_data [Hash]    Data for post request
  # @return [Array] response_code [Integer] and parsed_data [Hash]

  def api_request(verb, path, post_data=nil,
                  open_timeout: nil, read_timeout: nil, write_timeout: nil)
    url = expand_api_path(path)

    # See if we need an access token or a partner authentication token.
    partner_prefix  = "https://#{@config[:api_host]}#{API_BASE_PATH}/partner_accounts"
    partner_pattern = /\A#{Regexp.escape(partner_prefix)}(\/|\z)/
    if url =~ partner_pattern
      access_token = get_partner_authentication_token
    else
      # If we're in the token mutex, then we're already in the middle of
      # token processing.  Don't try to refresh the token in that case.
      # Specifically, we are processing the /users/me request in
      # exchange_authorization_code.
      unless Thread.current[:tesla_api_in_token_mutex]
        if token_state == :expired && !refresh_access_token
          return [500, { error: 'Unable to refresh access token' }]
        end
      end
      run_in_token_mutex { access_token = @tokens[:access_token] }
    end

    if access_token.nil? || access_token.empty?
      [401, { error: 'Not logged in' }]
    else
      (response_code, parsed_data) = request_data(
        access_token,
        verb,
        url,
        post_data,
        open_timeout:  open_timeout,
        read_timeout:  read_timeout,
        write_timeout: write_timeout
      )
      error = parsed_data&.dig(:error).to_s
      clear_tokens(access_token) if error =~ /invalid[ _]bearer[ _]token/
      [response_code, parsed_data]
    end
  end

  #--------------------

  # Make an authentication request to the Tesla Fleet API.
  # Returns response code and symbolized hash with response data.
  #
  # @param  verb      [Symbol] :GET or :POST
  # @param  path      [String] Path for request (possibly abbreviated)
  # @param  post_data [Hash]   Data for post request
  # @return [Array] response_code [Integer] and parsed_data [Hash]

  def auth_request(verb, path, post_data=nil,
                   open_timeout: nil, read_timeout: nil, write_timeout: nil)
    url = expand_auth_path(path)

    request_data(
      nil,
      verb,
      url,
      post_data,
      open_timeout:  open_timeout,
      read_timeout:  read_timeout,
      write_timeout: write_timeout
    )
  end

  #--------------------

  # Issue a GET or POST request to the specified Tesla Fleet API.
  # post_data and headers must be passed in as a hash.
  # Result is returned as response code and a symbolized hash (or nil if
  # there was a parser error).
  #
  # @param  access_token [String] Access token
  # @param  verb         [Symbol] :GET or :POST
  # @param  url          [String] URL for request
  # @param  post_data    [Hash]   Data for post request
  # @return [Array] response_code [Integer] and parsed_data [Hash]

  def request_data(access_token, verb, url, post_data=nil,
                   open_timeout: nil, read_timeout: nil, write_timeout: nil)
    headers = {}
    headers['Content-Type' ] = 'application/json'       if verb == :POST
    headers['Authorization'] = "Bearer #{access_token}" unless access_token.nil?

    @logger&.debug "HTTP: #{verb} #{uri_for_log(url)}"

    # Commented out to avoid possible data leaks.
    #@logger&.debug "Headers:\n#{headers.to_s}"     unless headers.empty?
    #@logger&.idebug "Post Data:\n#{post_data.to_s}" unless post_data.nil?

    raw_data = nil
    begin
      case verb
      when :GET
        response      = Https.get(url, headers,
                                  open_timeout:  open_timeout,
                                  read_timeout:  read_timeout,
                                  write_timeout: write_timeout)
        raw_data      = response&.body
        response_code = response&.code&.to_i
      when :POST
        response      = Https.post(url, headers, post_data&.to_json,
                                   open_timeout:  open_timeout,
                                   read_timeout:  read_timeout,
                                   write_timeout: write_timeout)
        raw_data      = response&.body
        response_code = response&.code&.to_i
      else
        raise "Invalid verb \"#{verb}\""
      end

    rescue OpenSSL::SSL::SSLError => e
      @logger&.error("TLS connection failed for #{uri_for_log(url)}")
      raise Tesla::TLSConnectionError, "TLS connection failed"

    rescue Errno::EINVAL,
           Errno::ECONNRESET,
           Errno::ECONNREFUSED,
           Errno::EHOSTUNREACH,
           EOFError,
           Net::OpenTimeout,
           Net::ReadTimeout,
           Net::WriteTimeout,
           Net::HTTPBadResponse,
           Net::HTTPHeaderSyntaxError,
           Net::ProtocolError,
           SocketError => e
      @logger&.info("Data request failed (#{e.class})")
      raw_data      = { error: "connection_error (#{e.class})" }.to_json
      response_code = 500
    end

    parsed_data = nil
    unless raw_data.nil? || raw_data.empty?
      begin
        parsed_data = JSON.parse(raw_data, {symbolize_names: true})
      rescue JSON::ParserError
        @logger&.warn "#{__method__}: error parsing response for #{uri_for_log(url)}"
        parsed_data = { error: "Unable to parse response" }
      end
    end

    [ response_code, parsed_data ]
  end

  #--------------------

  # Get access token for initial account registration.
  #
  # @return [String] Partner authentication token

  def get_partner_authentication_token
    post_data = {
      grant_type:    'client_credentials',
      client_id:     @config[:client_id    ],
      client_secret: @config[:client_secret],
      scope:         @config[:scopes       ],
      audience:      "https://#{@config[:api_host]}"
    }

    (response_code, data) = auth_request(:POST, 'token', post_data)

    #@logger&.debug "data = #{data.inspect}"

    if    response_code == 200 \
       && data.is_a?(Hash)     \
       && !data[:access_token].to_s.empty?

      data[:access_token]
    else
      @logger&.error 'Partner authentication error'
      nil
    end
  end

  #--------------------

  # Register public hostname to be used with Tesla API.
  #
  # @return [String] Whether registration was successful

  def register_account
    post_data = { domain: @config[:public_host] }

    (response_code, data) = api_request(:POST, 'partner_accounts', post_data)

    #@logger&.debug "data = #{data.inspect}"

    if    response_code == 200 \
       && data&.dig(:response, :domain) == @config[:public_host]

      'Registration successful'
    else
      "Registration unsuccessful\n#{data}"
    end
  end

  #--------------------

  # Generate a URL to be used with a web browser to log application in before
  # requests can be made.  This only has to be once as long as the
  # tesla_api_server app maintains a valid access token.  If the access token
  # expires, you must login again (the same generated URL can be used each
  # time to login again).
  #
  # @param  authorize_state [String] Random state string
  # @return [String] Tesla URL used to authorize access

  def generate_login_url(authorize_state)
    url_params = {
      response_type:            'code',
      client_id:                @config[:client_id      ],
      redirect_uri:             @config[:redirect_uri   ],
      scope:                    @config[:scopes         ],
      require_requested_scopes: true,
      state:                    authorize_state
    }

    uri = URI::HTTPS.build(
      host: @config[:auth_host],
      path: "#{AUTH_BASE_PATH}/authorize",
      query: URI.encode_www_form(url_params)
    )

    uri.to_s
  end

  #--------------------

  # Execute a block in a the token_mutex.
  #
  # @return [Object] Result of block

  def run_in_token_mutex
    result = nil

    if Thread.current[:tesla_api_in_token_mutex]
      result = yield if block_given?
    else
      @token_mutex.synchronize do
        Thread.current[:tesla_api_in_token_mutex] = true
        begin
          result = yield if block_given?
        ensure
          Thread.current[:tesla_api_in_token_mutex] = false
        end
      end
    end

    result
  end

  #--------------------

  # Clear all in memory and persisted tokens.
  #
  # @param access_token [String] Tesla access token

  def clear_tokens(access_token=nil)
    run_in_token_mutex do
      if access_token.nil? || @tokens[:access_token] == access_token
        @tokens.replace({})
        FileUtils.rm_f(@access_token_file)
      end
    end
  end

  #--------------------

  # Update the in-memory copy of the tokens with the results of a token
  # request.  Returns true if new tokens look good.  This method should
  # only be called while in the token_mutex.
  #
  # @param  response_code [Integer] Response code from authorization request
  # @param  token_data    [Hash]    Response data from authorization request
  # @return [Boolean] Tokens successfully updated

  def update_tokens(response_code, token_data)
    if token_data&.dig(:error).to_s =~ /invalid[ _]bearer[ _]token/
      @tokens.replace({})
      FileUtils.rm_f(@access_token_file)
      false
    elsif    response_code != 200                   \
          || token_data.nil?                        \
          || !token_data.is_a?(Hash)                \
          || token_data[:access_token ].to_s.empty? \
          || token_data[:expires_in   ].to_s.empty?

      # NOTE: if refresh token or obtained_at is omitted, old refresh token
      # must remain
      false
    else
      token_data[:refresh_token] ||= @tokens[:refresh_token]
      token_data[:obtained_at  ]   = Time.now.to_i

      if token_data[:refresh_token].to_s.empty?
        false
      else
        @tokens.replace(token_data)
        true
      end
    end
  end

  #--------------------

  # Save the in-memory token data to a file to allow connecting to API
  # without logging in again.  This method should # only be called while
  # in the token_mutex.
  #
  # @raise  [RuntimeError] If unable to persist data
  # @return [Boolean]      true if successful

  def save_tokens
    begin
      if @tokens.empty?
        clear_tokens
      else
        # Update the file as atomically as possible (depending on OS).
        state_dir = File.dirname(@access_token_file)
        if Dir.exist?(state_dir)
          mode = File.stat(state_dir).mode & 0777
          unless (mode | @config[:state_dir_perms]) == @config[:state_dir_perms]
            raise "State directory permissions are too permissive " \
                  "(#{mode.to_s(8)})"
          end
        else
          FileUtils.mkdir_p(state_dir, mode: @config[:state_dir_perms])
        end

        Tempfile.create(File.basename(@access_token_file),
                        File. dirname(@access_token_file) ) do |tmp_file|
          begin
            File.write(tmp_file.path, @tokens.to_json, perm: @config[:state_file_perms])
            File.rename(tmp_file.path, @access_token_file)
            File.chmod(@config[:state_file_perms], @access_token_file)
          end
        end
      end
    rescue SystemCallError => e
      raise "Unable to save tokens: #{e.message}"
    end

    true
  end

  #--------------------

  # Refresh the existing tokens.
  #
  # @return [Boolean] Whether tokens were valid and successfully persisted

  def refresh_access_token
    run_in_token_mutex do
      break false if @tokens[:refresh_token].to_s.empty?

      break true if token_state == :valid

      post_data = {
        grant_type:    'refresh_token',
        client_id:     @config[:client_id    ],
        client_secret: @config[:client_secret], # Shouldn't be needed for refresh_token
        refresh_token: @tokens[:refresh_token]
      }

      (response_code, token_data) = auth_request(:POST, 'token', post_data)

      saved_tokens = @tokens.dup
      if update_tokens(response_code, token_data)
        begin
          save_tokens
          true
        rescue RuntimeError
          @tokens.replace(saved_tokens)
          false
        end
      else
        @tokens.replace(saved_tokens)
        false
      end
    end
  end

  #--------------------

  # Send code we got from the authorization callback to get a fresh
  # set of tokens (include an access token).
  # Returns nil if exchange failed.
  #
  # @param  code [String] Authorization code provided by OAuth2 callback
  # @raise  [RuntimeError] If unable to persist token
  # @return [Array]        response_code [Integer] and auth_data [Hash]

  def exchange_authorization_code(code)
    auth_response_code = nil
    auth_data          = nil

    run_in_token_mutex do
      post_data = {
        grant_type:    'authorization_code',
        code:          code,
        client_id:     @config[:client_id    ],
        client_secret: @config[:client_secret],
        redirect_uri:  @config[:redirect_uri ]
      }

      (auth_response_code, auth_data) = auth_request(:POST, 'token', post_data)

      saved_tokens = @tokens.dup
      begin
        if !update_tokens(auth_response_code, auth_data)
          @tokens.replace(saved_tokens)
          auth_response_code = 503 if auth_response_code == 200
        else
          if @config[:tesla_email].nil?
            save_tokens
          else
            (api_response_code, api_data) = api_request(:GET, 'users/me')
            if api_response_code != 200
              @tokens.replace(saved_tokens)
              auth_response_code = 500
              auth_data          = { error: 'Unable to verify authenticated user' }
            elsif api_data&.dig(:response, :email) == @config[:tesla_email]
              begin
                save_tokens
              rescue StandardError
                @tokens.replace(saved_tokens)
                raise
              end
            else
              @tokens.replace(saved_tokens)
              auth_response_code = 403
            end
          end
        end
      rescue RuntimeError
        @tokens.replace(saved_tokens)
        raise
      end
    end

    [auth_response_code, auth_data]
  end

  #--------------------

  # Checks to see if id_or_vin is of a valid format.
  #
  # @param  id_or_vin [String] Tesla ID (not vehicle_id) or VIN
  # @return [Boolean] Whether id_or_vin looks validly formatted

  def id_or_vin_valid?(id_or_vin)
    # Tests below don't return true/false on their own.
    (!id_or_vin.nil? && id_or_vin =~ /\A[A-Z0-9]+\z/) ? true : false
  end

  #--------------------

  # Request a list of vehicles from the Tesla API.
  #
  # @return [Hash, NilClass] Hash with data from vehicles endpoint

  def get_vehicles
    (response_code, data) = api_request(:GET, 'vehicles')
    (response_code == 200) ? data&.dig(:response) : nil
  end

  #--------------------

  # Get specified vehicle's state from the Tesla API.
  #
  # @param  id_or_vin [String] Tesla ID (not vehicle_id) or VIN
  # @return [String] Vehicle state

  def get_vehicle_state(id_or_vin)
    unless id_or_vin_valid?(id_or_vin)
      raise "Invalid vehicle ID (#{id_or_vin})"
    end
    endpoint = "/vehicles/#{id_or_vin}"
    (response_code, data) = api_request(:GET, endpoint)
    if response_code == 401
      nil # Not logged in
    elsif response_code == 404
      '' # Vehicle not found
    elsif data&.dig(:error).to_s =~ /asleep/
      'asleep'
    else
      vehicle_state = data&.dig(:response, :state)
      case vehicle_state
      when 'offline'
        'asleep'
      when 'online'
        'online'
      when nil
        "unknown (#{response_code})"
      else
        "unknown state (#{vehicle_state})"
      end
    end
  end

  #--------------------

  # Wake up the specified vehicle.
  #
  # @param  id_or_vin [String] Tesla ID (not vehicle_id) or VIN
  # @return [Hash, NilClass] Hash with data from wake_up endpoint

  def wake_up_vehicle(id_or_vin)
    unless id_or_vin_valid?(id_or_vin)
      raise "Invalid vehicle ID (#{id_or_vin})"
    end

    endpoint = "vehicles/#{id_or_vin}/wake_up"
    (response_code, data) = api_request(:POST, endpoint)
    (response_code == 200) ? data : nil
  end

  #--------------------

  # Execute requests to one or more endpoints for one or more vehicle ids.
  # Return either the raw data collected (possibly in an array) or build up
  # a consolidated JSON result.
  #
  # @param  endpoints    [Array, String] One or more endpoints to process
  # @param  vins_or_ids  [String]  Comma separated string of IDs for vehicles
  # @param  post_data    [Hash]    Data to send with post requests (or nil)
  # @param  consolidated [Boolean] Whether to generated a consolidated hash
  # @return [String] JSON string with results of request(s)

  def process_endpoints(endpoints, vins_or_ids, post_data=nil, consolidated=false)
    unique_endpoints = find_endpoints(endpoints, vins_or_ids,
                                      post_data.nil? ? :GET : :POST)
    return nil if unique_endpoints.empty?

    post_count = unique_endpoints.count { |ep| ep[:verb] == :POST }
    raise "Cannot specify multiple post requests" if post_count > 1

    result_data = nil

    unique_endpoints.each do |unique_endpoint|
      verb      = unique_endpoint[:verb     ]
      endpoint  = unique_endpoint[:endpoint ]

      if [:vehicle_command, :car_server_command].include?(verb)
        vin = unique_endpoint[:vin ]
        issue_command(verb, endpoint, vin)
        next
      end

      ep = endpoint.sub(/^.*#{Regexp.escape(API_BASE_PATH)}\//, '')
      match = ep.match(/^vehicles\/(\w+)(?:\/|$)/)
      if match
        id_or_vin = match&.captures&.first
        if id_or_vin =~ /\A[a-z_]+\z/
          id_or_vin = nil
        elsif !id_or_vin_valid?(id_or_vin)
          raise "Invalid vehicle ID (#{id_or_vin})"
        end
      end

      (response_code, data) = api_request(verb, endpoint, post_data)

      #@logger&.debug "data          = #{data.inspect}"
      @logger&.debug "#{__method__}:response_code = #{response_code.inspect}"

      if consolidated
        # The requested vehicle id could either be a ID or a VIN (not vehicle_id).
        # Try to get the VIN, to put in the result.  If we can't,
        # fall back to putting the ID in the result (i.e. if requesting
        # by ID and vehicle is asleep).
        response = data&.dig(:response)
        if response&.is_a?(Array)
          response.each do |response_item|
            vid = response_item&.dig(:vin) || id_or_vin
            result_data = add_to_consolidated_result(
              result_data, endpoint, vid, {response: response_item}
            )
          end
        else
          vid = response&.dig(:vin) || id_or_vin
          result_data = add_to_consolidated_result(
            result_data, endpoint, vid, data
          )
        end
      elsif !data.nil?
        if result_data.nil? || result_data.empty?
          result_data = data
        else
          result_data = [ result_data ] unless result_data.is_a?(Array)
          result_data << data
        end
      end
    end

    #@logger&.debug "#{__method__): result_data = #{result_data.inspect}"

    result_data.nil? ? nil : result_data.to_json
  end

  #--------------------

  # Make a unique list of endpoints for the combination of supplied
  # endpoints (either single string or array) and a comma separated
  # list of IDs or VINs.
  #
  # @param  endpoints   [Array, String] One or more endpoints to process
  # @param  vins_or_ids [String]  Comma separated string of IDs for vehicles
  # @param  verb        [Symbol]  :GET or :POST
  # @return [Array] Endpoints identified

  def find_endpoints(endpoints, vins_or_ids, verb)
    return [] if endpoints.nil? || endpoints.empty?

    endpoints = [ endpoints ] unless endpoints.is_a?(Array)

    vehicles = case vins_or_ids
               when nil    then [ nil ]
               when String then vins_or_ids.split(/,/)
               when Array  then vins_or_ids
               else raise "Invalid vehicle ID type"
               end
    vehicles = [ nil ] if vehicles.empty?
    unique_endpoints = []
    vehicles&.each do |id_or_vin|
      endpoints.each do |endpoint|
        if Tesla::VehicleCommand::valid_command?(endpoint)
          new_endpoint = { verb: :vehicle_command, endpoint: endpoint, vin: id_or_vin }
        elsif Tesla::CarServerCommand::valid_command?(endpoint)
          new_endpoint = { verb: :car_server_command, endpoint: endpoint, vin: id_or_vin }
        else
          ep = endpoint.sub(/^.*#{Regexp.escape(API_BASE_PATH)}\//, '')
          match = ep.match(/^vehicles\/(\w+)(?:\/|$)/)
          if match
            vid = match.captures.first
            if vid =~ /\A[a-z_]+\z/
              # Not an endpoint with an ID
              vid = nil
            elsif !id_or_vin_valid?(vid)
              raise "Invalid vehicle ID (#{vid})"
            end
          else
            vid = id_or_vin
          end
          (verb, endpoint) = find_endpoint(endpoint, vid, verb)
          new_endpoint = { verb: verb, endpoint: endpoint }
        end

        unless unique_endpoints.include?(new_endpoint)
          unique_endpoints << new_endpoint
        end
      end
    end

    # Compress vehicle data endpoints into a single request.
    vd_hash              = nil
    vd_base              = nil
    vd_endpoints         = []
    compressed_endpoints = []
    unique_endpoints.each do |endpoint|
      pattern = /\A(.*#{Regexp.escape(API_BASE_PATH)}\/vehicles\/[^\/]+\/vehicle_data\?endpoints=)(\w+)\z/
      if    endpoint[:endpoint] =~ pattern  \
         && (vd_base.nil? || vd_base == $1) \
         && (vd_hash.nil? || vd_hash[:verb] == endpoint[:verb])
        vd_base       = $1
        vd_endpoints << $2
        vd_hash       = endpoint
      else
        compressed_endpoints << endpoint
      end
    end
    unless vd_base.nil?
      vd_hash[:endpoint] = "#{vd_base}#{vd_endpoints.join(';')}"
      compressed_endpoints << vd_hash
    end

    compressed_endpoints
  end

  #--------------------

  # Given a user provided endpoint, look through the list of legitimate
  # endpoints and find the matching endpoint.  Either a fully specified
  # endpoint may be specified or an abbreviated endpoint may be specified.
  # The user provided endpoint may be abbreviated in the following ways:
  # - Including "/api/1" or not
  # - Specifying "\\{vin}" to indicate using a vehicle_id specified in the
  #   config file or application command line.
  # - Omitting "/vehicles/\\{vin}" as a shorthand to vehicle endpoints.
  # - Specifying "location_data" (or other vehicle_data sub-requests) as a
  #   shorthand for "vehicle_data?endpoints=location_data".
  # - Omitting "?vin=\\{vin}" on endpoints that require it.
  #
  # @param  raw_endpoint   [String] One or more endpoints to process
  # @param  id_or_vin      [String] Tesla ID (not vehicle_id) or VIN
  # @param  requested_verb [Symbol] :GET or :POST
  # @return [Array] verb [Symbol], endpoint [String]
  # @raise  [RuntimeError] If raw_endpoint or id_or_vin invalid

  def find_endpoint(raw_endpoint, id_or_vin, requested_verb)
    @logger&.debug "raw_endpoint = #{raw_endpoint}"

    # Need to replace {vin} before calling URI.parse.
    if id_or_vin.nil? || id_or_vin.empty?
      if raw_endpoint =~ /\{vin\}/
        raise "Invalid vehicle ID (#{id_or_vin})"
      end
      ep = raw_endpoint
    else
      unless id_or_vin_valid?(id_or_vin)
        raise "Invalid vehicle ID (#{id_or_vin})"
      end
      ep = raw_endpoint.gsub(/\{vin\}/, id_or_vin.to_s)
    end

    begin
      uri = URI.parse(normalize_endpoint(ep))
    rescue URI::InvalidURIError
      raise "Invalid endpoint #{raw_endpoint}"
    end

    raise "Unable to parse endpoint #{raw_endpoint}" if uri.path.to_s.empty?

    @logger&.debug "path = #{uri.path}"

    (verb, match) = match_endpoint(uri, requested_verb, id_or_vin)

    endpoint = assemble_endpoint(uri, match, id_or_vin)

    @logger&.debug "final endpoint = #{endpoint}"

    [verb, endpoint]
  end

  #--------------------

  # Clean up the raw_endpoint so that it is in a normalized state for
  # matching.
  #
  # @param  raw_endpoint [String] One or more endpoints to process
  # @return [String] Normalized endpoint
  # @raise  [RuntimeError] If raw_endpoint invalid

  def normalize_endpoint(raw_endpoint)
    # Silently strip off the host information from the endpoint so that we
    # don't make requests from an unexpected host.
    begin
      uri = URI.parse(raw_endpoint)
    rescue URI::InvalidURIError
      uri = nil
    end
    if uri.nil?
      hostless_endpoint = raw_endpoint
    else
      if !uri.host.nil? && uri.host != config[:api_host]
        raise "Invalid host #{uri.host} (must be #{config[:api_host]})"
      end
      # First part of path may be host name if no scheme or host.
      if uri.scheme.nil? && uri.host.nil? && uri.path =~ /^(.+)#{Regexp.escape(API_BASE_PATH)}\//
        raise "Invalid host #{$1} (must be #{config[:api_host]})"
      end
      hostless_endpoint  = uri.path
      hostless_endpoint += "?#{uri.query}" unless uri.query.nil?
    end

    # Remove some unnecessary stuff from the front of the endpoint.
    endpoint = hostless_endpoint \
      &.sub(/^.*#{Regexp.escape(API_BASE_PATH)}/, '') \
      &.sub(/^\//, '')

    # Handle custom endpoint shorthand to request vehicle data sub-requests.
    VEHICLE_DATA_ENDPOINTS.include?(endpoint) \
     ? "vehicle_data?endpoints=#{endpoint}" : endpoint
  end

  #--------------------

  # Find the best match for our uri in the list of Tesla Fleet API endpoints.
  #
  # @param  uri            [URI]    URI to find a match for
  # @param  requested_verb [Symbol] :GET or :POST
  # @param  id_or_vin      [String] Tesla ID (not vehicle_id) or VIN
  # @return [Array] verb [Symbol], match [String]
  # @raise  [RuntimeError] If uri doesn't match a single entry

  def match_endpoint(uri, requested_verb, id_or_vin)
    uri.query&.gsub!(/\{vin\}/, id_or_vin.to_s)

    # Find the endpoint in the list of valid endpoints.
    vehicle_prefix = "vehicles/#{id_or_vin}/"
    match          = nil
    match_query    = nil
    verb           = nil
    post_match     = nil

    ENDPOINTS.each do |match_endpoint|
      match_path = match_endpoint[:endpoint].dup
      match_path.gsub!(/\{vin\}/, id_or_vin.to_s)
      match_path.gsub!(/\{\w+\}/, '_PARAM_')
      match_uri = URI.parse(match_path)
      match_pattern = /\A#{Regexp.escape(match_uri.path).gsub(/_PARAM_/, '[^#&%\?\/\\\s]+')}\z/

      [:none,:prefix].each do |adjustment|
        # Make various adjustments to the endpoint to see if we can get
        # a match with the current item from the endpoints list.
        case adjustment
        when :none
          adjusted_endpoint = uri.path
        when :prefix
          adjusted_endpoint = vehicle_prefix + uri.path
        end

        @logger&.debug "adjusted_endpoint = #{adjusted_endpoint}"
        @logger&.debug "requested_verb    = #{requested_verb   }"
        @logger&.debug "match_uri.path    = #{match_uri.path   }"

        if adjusted_endpoint =~ match_pattern
          if ![:GET, :POST].include?(match_endpoint[:verb])
            next # Ignore endpoints that aren't for GET or POST
          elsif match_endpoint[:verb] == :POST && requested_verb == :GET
            # Endpoints like wake_up do not need post_data (thus will come here
            # as a request for a GET).  So, we'll keep track of it and if we
            # didn't find a matching GET, we'll use the POST instead.
            post_match = adjusted_endpoint
            @logger&.debug "post match = #{adjusted_endpoint}"
          elsif match_endpoint[:verb] != requested_verb
            next
          else
            # Make sure required query parameters are specified.  We don't
            # care about the format of the parameters values or if extra
            # parameters are specified.  The Tesla Fleet API will take care
            # of reporting errors if those things if they are a problem.
            # We shouldn't have repeated parameters, so it's ok if repeated
            # parameters get compressed out.
            query_match = true
            match_query_hash = match_uri.query.nil? \
                               ? {} : Rack::Utils.parse_nested_query(match_uri.query)
            uri_query_hash   = uri.query.nil? \
                               ? {} : Rack::Utils.parse_nested_query(uri.query)
            match_query_hash.transform_keys!(&:to_sym)
            uri_query_hash.transform_keys!(&:to_sym)
            match_query_hash.each do |key, match_value|
              uri_value = uri_query_hash[key]
              next if key == :vin && uri_value.nil? # Will be added later
              unless uri_value.nil? # If we are missing a required value, fail
                next if match_value =~ /_PARAM_/ # URI query param in match query
                next if uri_value == match_value # Constant param value differs
              end
              query_match = false # Undefined URI param or value doesn't match
            end

            # Got a good match (both path and required parameters).
            if query_match
              if match.nil?
                # Add vin parameter to query if match specifies it and request
                # doesn't have it.
                if match_query_hash.key?(:vin) && !uri_query_hash.key?(:vin)
                  unless id_or_vin_valid?(match_query_hash[:vin])
                    query_match = false
                    next
                  end
                  uri_query_hash[:vin] = match_query_hash[:vin]
                  uri.query = URI.encode_www_form(uri_query_hash)
                end

                match = adjusted_endpoint
                @logger&.debug "match = #{match}"
                verb = match_endpoint[:verb]
                break # Break out of adjustment loop
              else
                raise "Duplicate matching endpoint" \
                      " #{verb} \"#{adjusted_endpoint}\""  \
                      " and #{match_endpoint[:verb]} \"#{match}\""
              end
            end
          end
        end
      end
    end

    # If we didn't find an exact match, see if we find a match with
    # the POST verb.
    if match.nil?
      if post_match.nil?
        raise "Invalid endpoint \"#{uri.path}\""
      else
        match = post_match
        verb  = :POST
      end
    end

    unless match.nil?
      uri.path  = match
      uri.query = match_query unless match_query.nil?
      match = uri.to_s
    end

    [verb, match]
  end

  #--------------------

  # Combine the match with our initial uri to get a final url.
  #
  # @param  uri       [URI]    URI to find a match for
  # @param  match     [String] Matching endpoint
  # @param  id_or_vin [String] Tesla ID (not vehicle_id) or VIN
  # @return [String] Final URL

  def assemble_endpoint(uri, match, id_or_vin)
    m = match.gsub(/\{vin\}/, id_or_vin.to_s)
    match_uri = URI.parse(m)
    uri.path = "#{API_BASE_PATH}/#{match_uri.path}"

    # Add query params to uri.
    query_hash = {}
    [match_uri.query, uri.query].each do |q|
      unless q.nil? || q.empty?
        # We shouldn't have repeated parameters, so it's ok if repeated
        # parameters get compressed out.
        Rack::Utils.parse_nested_query(q).each do |key, value|
          Array(value).each do |v|
            v.gsub!(/\{vin\}/, id_or_vin.to_s)
            query_hash[key] = v
          end
        end
      end
    end
    uri.query = URI.encode_www_form(query_hash) unless query_hash.empty?

    url = uri.to_s
    url.gsub!(/\{vin\}/, id_or_vin.to_s)

    url
  end

  #--------------------

  # Add the specified raw_data to the consolidated result hash that may
  # contain data from multiple requests.  This is primarily for being
  # passed on to the MQTT polling program.
  #
  # @param result_data [Hash]   Consolidated data to this point
  # @param endpoint    [String] Request endpoint called
  # @param vin         [Integer, String] ID of vehicle (not vehicle_id) or VIN
  # @param parsed_data [Hash]   Request data to add to consolidated result

  def add_to_consolidated_result(result_data, endpoint, vin, parsed_data)
    # Build data that can be represented in a single hash if multiple
    # endpoints are requested.
    if parsed_data&.key?(:response)
      response = parsed_data[:response]
      if response.nil?
        if parsed_data&.dig(:error).to_s !~ /asleep/
          # Don't put the "asleep" message in the response, set
          # communication_status, a bit later, instead.
          response = { error: parsed_data[:error] }
        elsif parsed_data.key?(:message)
          response = { message: parsed_data[:message] }
        end
      end
    end

    vehicle_request      = false
    communication_status = nil
    ep = endpoint.sub(/^.*#{Regexp.escape(API_BASE_PATH)}\//, '')
    match = ep.match(/^vehicles\/\w+(?:\/|$)/)
    if match
      vehicle_request = true
      if parsed_data.nil?
        communication_status = 'Not logged in'
      elsif !response&.key?(:error) && !response&.key?(:message)
        error = parsed_data[:error].to_s # to_s to handle nil
        communication_status = case error
                               when ''       then 'online'
                               when /asleep/ then 'asleep'
                               else               'error'
                               end
      end
    end

    @logger&.debug("communication_status = #{communication_status.inspect}")
    if response.is_a?(Hash)
      @logger&.debug("response fields = #{response.keys.map(&:to_s).sort.join(', ')}")
    else
      @logger&.debug("response type = #{response.class}")
    end

    if vehicle_request
      unless response.nil?
        result_data ||= {}
        result_data[:vehicles] ||= {}
        # NOTE: drive_state from vehicle_data and location_data will be merged.
        result_data[:vehicles][vin] ||= {}
        result_data[:vehicles][vin].deep_merge!(response)
      end
      unless communication_status.nil?
        result_data ||= {}
        result_data[:vehicles] ||= {}
        result_data[:vehicles][vin] ||= {}
        result_data[:vehicles][vin][:communication_status] = communication_status
      end
    else
      result_data ||= {}
      result_data.replace(response)
    end

    result_data
  end

  #--------------------

  # Issue a car service command or vehicle command.
  #
  # @param verb [Symbol] :car_service_command or :vehicle_command
  # @param cmd [String]  Command (with parameters) to run
  # @param vin [String]  VIN of vehicle to run command against
  # @return [Hash] Results of command
  # @raise [RuntimeError] Unable to get refresh token, car asleep

  def issue_command(verb, cmd, vin)
    # If we're in the token mutex, then we're already in the middle of
    # token processing.  Don't try to refresh the token in that case.
    # Specifically, we are processing the /users/me request in
    # exchange_authorization_code.
    unless Thread.current[:tesla_api_in_token_mutex]
      if token_state == :expired && !refresh_access_token
        raise 'Unable to refresh access token'
      end
    end
    access_token = nil
    run_in_token_mutex { access_token = @tokens[:access_token] }

    raise 'Not logged in' if access_token.nil? || access_token.empty?

    begin
      @command_mutex.synchronize do
        case verb
        when :car_server_command
          Tesla::CarServerCommand.command(
            self,
            vin,
            cmd,
            logger: Tesla::SafeLogger.new(@logger)
          )

        when :vehicle_command
          Tesla::VehicleCommand.command(
            self,
            vin,
            cmd,
            logger: Tesla::SafeLogger.new(@logger)
          )
        end
      end
    rescue Tesla::FleetAPIError => e
      if e.status == 408
        raise 'Vehicle is asleep'
      else
        raise
      end
    end
  end

  private

  # Sanitize a URL to be put in a log message
  #
  # @param url [String] URL to sanitize
  # @return [String] Sanitized URL

  def uri_for_log(url)
    uri  = URI.parse(url)
    path = uri.path.to_s
    path = path.gsub(%r{/vehicles/[^/]+}, '/vehicles/[vehicle]')
    path
  rescue URI::InvalidURIError
    "<invalid URL>"
  end
end

#----------------------------------------------------------------------------
