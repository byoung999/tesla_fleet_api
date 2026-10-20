require_relative "../test_helper"

class TestTeslaSession < Minitest::Test
  def setup
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
        epoch: "a" * 16,
        counter: 100,
        clock_time: Time.now.to_i,
        routing_address: "b" * 16,
      )
  end

  def test_initial_counter
    assert_equal(
      100,
      @session.current_counter
    )
  end

  def test_advance_counter
    @session.advance_counter

    assert_equal(
      101,
      @session.current_counter
    )
  end

  def test_vehicle_time
    time_now = Time.now.to_i
    assert_equal(
      time_now + @session.instance_variable_get(:@clock_offset),
      @session.vehicle_time(time_now)
    )
  end

  def test_session_state
    assert_equal(
      16,
      @session.epoch.bytesize
    )

    assert_equal(
      16,
      @session.routing_address.bytesize
    )

    assert_equal(
      16,
      @session.session_key.bytesize
    )
  end

  def test_clock_offset_survives_serialization
    session =
      build_session(
        clock_time: 10_000,
        local_time: 9_500
      )

    restored =
      Tesla::Session.from_h(
        session.to_h,
        private_key: @private_key
      )

    assert_equal(
      500,
      restored.clock_offset
    )

    assert_equal(
      10_500,
      restored.vehicle_time(10_000)
    )
  end

  def test_counter_cannot_decrease
    session =
      build_session(
        counter: 100
      )

    assert_raises(Tesla::ProtocolError) do
      session.update_counter(99)
    end

    assert_equal(
      100,
      session.current_counter
    )
  end

  def test_counter_can_increase
    session =
      build_session(
        counter: 100
      )

    session.update_counter(105)

    assert_equal(
      105,
      session.current_counter
    )
  end

  def test_counter_never_moves_backward
    session =
      build_session(counter: 100)

    threads =
      10.times.map do
        Thread.new do
          10.times do
            session.advance_counter
          end
        end
      end

    threads.each(&:join)

    assert_equal(
      200,
      session.current_counter
    )
  end

  def test_counter_overflow_is_rejected
    session =
      build_session(
        counter: 0xffff_ffff
      )

    assert_raises(Tesla::ProtocolError) do
      session.advance_counter
    end

    assert_equal(
      0xffff_ffff,
      session.current_counter
    )
  end

  def test_clock_regression_is_rejected
    session =
      build_session(
        clock_time: 1_000
      )

    assert_raises(Tesla::ProtocolError) do
      session.update_clock(999)
    end

    assert_equal(
      1_000,
      session.clock_time
    )
  end

  def test_rejects_cached_session_with_mismatched_session_key
    data =
      @session.to_h

    data["session_key"] =
      ("\xAA".b * 16).unpack1("H*")

    assert_raises(ArgumentError) do
      Tesla::Session.from_h(
        data,
        private_key: @private_key
      )
    end
  end

  def test_rejects_cached_session_with_wrong_private_key
    wrong_private_key =
      Tesla::Crypto.generate_key

    assert_raises(ArgumentError) do
      Tesla::Session.from_h(
        @session.to_h,
        private_key: wrong_private_key
      )
    end
  end

  private

  def build_session(
    counter: 100,
    clock_time: Time.now.to_i,
    local_time: Time.now.to_i,
    epoch: "a" * 16,
    routing_address: "b" * 16
  )
    Tesla::Session.new(
      private_key: @private_key,
      vehicle_public_key: @vehicle_public_key,
      session_key: @session_key,
      epoch: epoch,
      counter: counter,
      clock_time: clock_time,
      routing_address: routing_address,
      local_time: local_time
    )
  end

end
