require_relative "../test_helper"

class TestTeslaMetadata < Minitest::Test
  def test_serializes_string
    metadata =
      Tesla::Metadata.new

    metadata.put(
      2,
      "abc"
    )

    assert_equal(
      "0203616263ff",
      metadata.serialize.unpack1("H*")
    )
  end

  def test_serializes_integer_big_endian
    metadata =
      Tesla::Metadata.new

    metadata.put(
      5,
      100
    )

    assert_equal(
      "050400000064ff",
      metadata.serialize.unpack1("H*")
    )
  end

  def test_serializes_in_tag_order
    metadata =
      Tesla::Metadata.new

    metadata.put(5, 100)
    metadata.put(2, "abc")

    assert_equal(
      "0203616263050400000064ff",
      metadata.serialize.unpack1("H*")
    )
  end

  def test_serializes_flags
    metadata =
      Tesla::Metadata.new

    metadata.put(
      7,
      2
    )

    assert_equal(
      "070400000002ff",
      metadata.serialize.unpack1("H*")
    )
  end

  def test_integer_range
    metadata =
      Tesla::Metadata.new

    assert_raises(ArgumentError) do
      metadata.put(1, -1)
    end

    assert_raises(ArgumentError) do
      metadata.put(1, 0x1_0000_0000)
    end
  end
end
