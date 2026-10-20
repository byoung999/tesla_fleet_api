# frozen_string_literal: true

require_relative 'test_helper'
# Can't use require_relative if file doesn't have a .rb extension
load File.expand_path('../bin/start_ngrok', __dir__)

class StartNgrokTest < Minitest::Test

  def test_start_ngrok_builds_expected_command
    calls = []

    executor = lambda do |*args|
      calls << args
    end

    config = {
      public_host: 'example.com',
      local_port: 8089
    }

    start_ngrok(
      config,
      '/etc/ngrok.yaml',
      '/etc/ngrok_tesla_policy.yaml',
      executor
    )

    assert_equal(
      [
        [
          'ngrok',
          'http',
          '--url=example.com',
          '8089',
          '--config',
          '/etc/ngrok.yaml',
          '--traffic-policy-file',
          '/etc/ngrok_tesla_policy.yaml'
        ]
      ],
      calls
    )
  end

  def test_start_ngrok_does_not_use_shell_interpretation
    calls = []

    executor = lambda do |*args|
      calls << args
    end

    config = {
      public_host: 'example.com; touch /tmp/pwned',
      local_port: 8089
    }

    start_ngrok(
      config,
      '/etc/ngrok.yaml',
      '/etc/ngrok_tesla_policy.yaml',
      executor
    )

    assert_equal 1, calls.length

    command = calls.first

    assert_equal 'ngrok', command[0]
    assert_equal 'http', command[1]

    assert_equal(
      '--url=example.com; touch /tmp/pwned',
      command[2]
    )

    assert_equal '8089', command[3]
  end

  def test_start_ngrok_preserves_arguments_containing_spaces
    calls = []

    executor = lambda do |*args|
      calls << args
    end

    config = {
      public_host: 'example.com',
      local_port: 8089
    }

    start_ngrok(
      config,
      '/path with spaces/ngrok.yaml',
      '/path with spaces/ngrok_tesla_policy.yaml',
      executor
    )

    assert_equal(
      [
        'ngrok',
        'http',
        '--url=example.com',
        '8089',
        '--config',
        '/path with spaces/ngrok.yaml',
        '--traffic-policy-file',
        '/path with spaces/ngrok_tesla_policy.yaml'
      ],
      calls.first
    )
  end

  def test_start_ngrok_defaults_local_port
    calls = []

    executor = lambda do |*args|
      calls << args
    end

    config = {
      public_host: 'example.com'
    }

    start_ngrok(
      config,
      '/etc/ngrok.yaml',
      '/etc/ngrok_tesla_policy.yaml',
      executor
    )

    assert_equal '8089', calls.first[3]
  end
end
