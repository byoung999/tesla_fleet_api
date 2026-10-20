# frozen_string_literal: true

module Tesla

  # Encodes the compact tag/length/value metadata section used inside Tesla
  # RoutableMessages. Values are stored in tag order and serialized with a 0xff
  # terminator.
  #
  # @see https://developers.tesla.com/docs/fleet-api

  class Metadata
    TAG_END = 0xff

    # Creates an empty metadata collection. Tags are accumulated until
    # serialize is called.
    #
    # @return [void] the operation result.

    def initialize
      @values = {}
    end

    # Stores an integer or binary-string metadata value under a tag and returns
    # the Metadata instance so callers can build metadata fluently.
    #
    # @param [Integer] tag value used by the operation.
    # @param [Integer, String] value value used by the operation.
    # @return [Tesla::Metadata] the operation result.

    def put(tag, value)
      unless Integer === tag && tag.between?(0, 254)
        raise ArgumentError,
              "metadata tag must be between 0 and 254"
      end

      @values[tag] = encode_value(value)

      self
    end

    # Stores a single unsigned byte as a metadata value. It delegates tag
    # validation and encoding to put.
    #
    # @param [Integer] tag value used by the operation.
    # @param [Integer, String] value value used by the operation.
    # @return [Tesla::Metadata] the operation result.

    def put_byte(tag, value)
      unless Integer === value && value.between?(0, 255)
        raise ArgumentError,
              "metadata byte value out of range"
      end

      put(tag, [value].pack("C"))
    end

    # Returns the encoded binary value currently associated with a metadata
    # tag, raising KeyError when the tag has not been added.
    #
    # @param [Integer] tag value used by the operation.
    # @return [String] the requested protocol value.

    def value(tag)
      @values.fetch(tag)
    end

    # Serializes all metadata entries in ascending tag order as
    # tag/length/value records followed by the protocol 0xff end marker.
    #
    # @return [String] the requested protocol value.

    def serialize
      result = +"".b

      @values
        .sort_by { |tag, _| tag }
        .each do |tag, value|

        result << [tag].pack("C")
        result << [value.bytesize].pack("C")
        result << value
      end

      result << [TAG_END].pack("C")

      result
    end

    private

    # Converts a supported Ruby metadata value into its protocol byte
    # representation: big-endian uint32 for integers or binary bytes for strings.
    #
    # @param [Integer, String] value value used by the operation.
    # @return [String] the command result or constructed protocol value.

    def encode_value(value)
      case value
      when Integer
        unless value.between?(0, 0xffffffff)
          raise ArgumentError,
                "integer metadata value out of range"
        end

        [value].pack("N")

      when String
        value.b

      else
        raise ArgumentError,
              "unsupported metadata value: #{value.class}"
      end
    end
  end
end
