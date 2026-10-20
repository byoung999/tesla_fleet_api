require_relative "../test_helper"

class TestSessionCache < Minitest::Test
  def setup
    @directory =
      Dir.mktmpdir("tesla-session-test")

    @path =
      File.join(
        @directory,
        "session.json"
      )

    @private_key =
      Tesla::Crypto.generate_key

    @vehicle_key =
      Tesla::Crypto.generate_key

    @vehicle_public_key =
      Tesla::Crypto.public_key_from_bytes(
        Tesla::Crypto.encoded_public_key(
          @vehicle_key
        )
      )

    @session_key =
      Tesla::Crypto.session_key(
        @private_key,
        @vehicle_public_key
      )

    @session =
      Tesla::Session.new(
        private_key: @private_key,
        vehicle_public_key: @vehicle_public_key,
        session_key: @session_key,
        epoch: "E" * 16,
        counter: 123,
        clock_time: 1_000,
        routing_address: "R" * 16,
        clock_offset: 250
      )

    @cache =
      Tesla::SessionCache.new(
        @path
      )
  end

  def teardown
    FileUtils.remove_entry(
      @directory
    )
  end

  def test_save_and_load
    assert(
      @cache.save(@session)
    )

    data =
      @cache.load

    refute_nil(data)

    restored =
      Tesla::Session.from_h(
        data,
        private_key: @private_key
      )

    assert_equal(
      @session.session_key,
      restored.session_key
    )

    assert_equal(
      @session.epoch,
      restored.epoch
    )

    assert_equal(
      @session.current_counter,
      restored.current_counter
    )

    assert_equal(
      @session.clock_time,
      restored.clock_time
    )

    assert_equal(
      @session.clock_offset,
      restored.clock_offset
    )

    assert_equal(
      @session.routing_address,
      restored.routing_address
    )
  end

  def test_cache_file_is_private
    @cache.save(@session)

    mode =
      File.stat(@path).mode & 0o777

    assert_equal(
      0o600,
      mode
    )
  end

  def test_corrupt_json_is_deleted
    File.write(
      @path,
      "{not valid json"
    )

    assert_nil(
      @cache.load
    )

    refute(
      File.exist?(@path)
    )
  end

  def test_missing_field_is_deleted
    @cache.save(@session)

    data =
      JSON.parse(
        File.read(@path)
      )

    data.delete("session_key")

    File.write(
      @path,
      JSON.generate(data)
    )

    assert_nil(
      @cache.load
    )

    refute(
      File.exist?(@path)
    )
  end

  def test_save_is_atomic
    @cache.save(@session)

    refute(
      Dir.glob(
        File.join(
          @directory,
          ".session-*.tmp"
        )
      ).any?
    )
  end

  def test_delete_when_missing_is_safe
    assert_nil(
      @cache.delete
    )
  end

  def test_delete_returns_true_when_file_exists
    @cache.save(@session)

    assert(
      File.file?(@path)
    )

    result =
      @cache.delete

    assert_equal(
      true,
      result
    )

    refute(
      File.exist?(@path)
    )
  end

  def test_concurrent_writes_leave_valid_json
    cache =
      Tesla::SessionCache.new(@path)

    sessions =
      10.times.map do |index|
        build_session(
          counter: 100 + index
        )
      end

    threads =
      sessions.map do |session|
        Thread.new do
          cache.save(session)
        end
      end

    threads.each(&:join)

    data = cache.load

    refute_nil data

    assert(
      data["counter"].between?(100, 109)
    )
  end

  def test_load_discards_malformed_json
    File.write(
      @path,
      "{ this is not valid JSON"
    )

    assert_nil(
      @cache.load
    )

    refute(
      File.exist?(@path)
    )
  end

  def test_load_discards_out_of_range_counter
    data =
      @session.to_h.merge(
        "counter" => 0x1_0000_0000
      )

    File.write(
      @path,
      JSON.generate(data)
    )

    assert_nil(
      @cache.load
    )

    refute(
      File.exist?(@path)
    )
  end

  def test_save_creates_file_with_owner_only_permissions
    @cache.save(@session)

    mode =
      File.stat(@path).mode & 0o777

    assert_equal(
      0o600,
      mode
    )
  end

  def test_load_discards_invalid_session_key_length
    data =
      @session.to_h.merge(
        "session_key" => "00"
      )

    File.write(
      @path,
      JSON.generate(data)
    )

    assert_nil(
      @cache.load
    )

    refute(
      File.exist?(@path)
    )
  end

  def test_load_discards_invalid_epoch_length
    data =
      @session.to_h.merge(
        "epoch" => "00"
      )

    File.write(
      @path,
      JSON.generate(data)
    )

    assert_nil(
      @cache.load
    )

    refute(
      File.exist?(@path)
    )
  end

  def test_load_discards_invalid_routing_address_length
    data =
      @session.to_h.merge(
        "routing_address" => "00"
      )

    File.write(
      @path,
      JSON.generate(data)
    )

    assert_nil(
      @cache.load
    )

    refute(
      File.exist?(@path)
    )
  end

  def test_load_discards_invalid_hex
    data =
      @session.to_h.merge(
        "session_key" => "Z" * 32
      )

    File.write(
      @path,
      JSON.generate(data)
    )

    assert_nil(
      @cache.load
    )

    refute(
      File.exist?(@path)
    )
  end

  def test_reserve_counter_increments_and_persists_session
    @cache.save(
      @session
    )

    reserved =
      @cache.reserve_counter(
        private_key: @private_key,
        session: @session
      )

    assert_equal(
      124,
      reserved.current_counter
    )

    data =
      @cache.load

    assert_equal(
      124,
      data.fetch("counter")
    )
  end

  def test_reserve_counter_uses_newer_cached_counter
    cached_session =
      build_session(
        counter: 200
      )

    @cache.save(
      cached_session
    )

    local_session =
      build_session(
        counter: 100
      )

    reserved =
      @cache.reserve_counter(
        private_key: @private_key,
        session: local_session
      )

    assert_equal(
      201,
      reserved.current_counter
    )
  end

  private

  def build_session(
    counter: 123,
    clock_time: 1_000,
    epoch: "E" * 16,
    routing_address: "R" * 16
  )
    Tesla::Session.new(
      private_key: @private_key,
      vehicle_public_key: @vehicle_public_key,
      session_key: @session_key,
      epoch: epoch,
      counter: counter,
      clock_time: clock_time,
      routing_address: routing_address,
      local_time: clock_time - 250
    )
  end

end
