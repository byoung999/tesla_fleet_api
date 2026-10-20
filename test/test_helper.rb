# frozen_string_literal: true

require 'bundler/setup'
require 'minitest/autorun'
require 'tmpdir'
require 'json'
require "openssl"
require "securerandom"

$LOAD_PATH.unshift(File.expand_path('../lib'                        , __dir__))
$LOAD_PATH.unshift(File.expand_path('../lib/signed_command'         , __dir__))
$LOAD_PATH.unshift(File.expand_path('../lib/signed_command/protobuf', __dir__))

require 'Config'
require 'TeslaAPI'

require "crypto"
require "metadata"
require "session"
require "session_cache"
require "protobuf_adapter"
require "fleet_transport"
require "vehicle_command"
require "car_server_command"
require "safe_logger"
require "errors"
require "error_classifier"

require "protobuf/universal_message_pb"
require "protobuf/signatures_pb"
require "protobuf/vcsec_pb"
require "protobuf/car_server_pb"

class TeslaAPITest < Minitest::Test
  TEST_CONFIG = {
    public_host:    'example.com',
    client_id:      'test-client',
    client_secret:  'test-secret',
    tesla_email:    'bill@example.com',
    session_secret: '0000000000000000000000000000000000000000000000000000000000000000',
    vehicle_id:     '1234567890123456',
  }.freeze

  def setup
    @tmpdir = Dir.mktmpdir('tesla-api-test')

    File.write(
      File.join(@tmpdir, 'config.json'),
      JSON.generate(TEST_CONFIG.merge(state_dir: @tmpdir)),
      perm: 0600
    )

    @api = TeslaAPI.new(@tmpdir, 'config.json')
  end

  def teardown
    FileUtils.remove_entry(@tmpdir) if @tmpdir && File.exist?(@tmpdir)
  end
end

class SilentLogger
  def debug(*)
  end

  def info(*)
  end

  def warn(*)
  end

  def error(*)
  end
end

class RecordingLogger
  attr_reader :events

  def initialize
    @events = []
  end

  def debug(event, fields = {})
    @events << [:debug, event, fields]
  end

  def info(event, fields = {})
    @events << [:info, event, fields]
  end

  def warn(event, fields = {})
    @events << [:warn, event, fields]
  end

  def error(event, fields = {})
    @events << [:error, event, fields]
  end
end
