# frozen_string_literal: true

require "openssl"
require "digest"

module Tesla

  # Cryptographic primitives used by the Tesla signed-command implementation.
  # The module contains P-256 key conversion, ECDH session-key derivation,
  # protocol-specific HMAC keys, constant-time comparison, AES-128-GCM
  # decryption, and SHA-256 helpers.
  #
  # @see https://developers.tesla.com/docs/fleet-api

  module Crypto
    CURVE = "prime256v1"

    module_function


    # Generates the application-side P-256 private key used during the Tesla
    # session handshake.
    #
    # @return [OpenSSL::PKey::EC] the command result or constructed protocol value.

    def generate_key
      OpenSSL::PKey::EC.generate(CURVE)
    end


    # Returns Tesla's 65-byte uncompressed P-256 public-key encoding
    # (`04 || X || Y`). This is the wire representation used in
    # session-establishment messages.
    #
    # @param [OpenSSL::PKey::EC] key value used by the operation.
    # @return [String] the requested protocol value.

    def encoded_public_key(key)
      public_key =
        key.public_key

      bytes =
        public_key.to_octet_string(:uncompressed)

      unless bytes.bytesize == 65
        raise ArgumentError,
              "expected 65-byte P-256 public key"
      end

      unless bytes.getbyte(0) == 0x04
        raise ArgumentError,
              "expected uncompressed EC point"
      end

      bytes
    end


    # Converts Tesla's 65-byte uncompressed P-256 public-key encoding into an
    # OpenSSL public key. The method builds SubjectPublicKeyInfo DER explicitly
    # because OpenSSL 3 treats PKey objects as immutable.
    #
    # @param [String] bytes value used by the operation.
    # @return [OpenSSL::PKey::EC] the command result or constructed protocol value.

    def public_key_from_bytes(bytes)
      unless bytes.is_a?(String) && bytes.bytesize == 65
        raise ArgumentError,
              "expected 65-byte P-256 public key"
      end

      unless bytes.getbyte(0) == 0x04
        raise ArgumentError,
              "expected uncompressed EC point"
      end

      algorithm =
        OpenSSL::ASN1::Sequence.new(
          [
            OpenSSL::ASN1::ObjectId.new("id-ecPublicKey"),
            OpenSSL::ASN1::ObjectId.new("prime256v1")
          ]
        )

      public_key_bit_string =
        OpenSSL::ASN1::BitString.new(bytes)

      subject_public_key_info =
        OpenSSL::ASN1::Sequence.new(
          [
            algorithm,
            public_key_bit_string
          ]
        )

      OpenSSL::PKey.read(
        subject_public_key_info.to_der
      )
    end


    # Performs P-256 ECDH with the local private key and vehicle public key and
    # returns the 32-byte shared-point X coordinate used by the Tesla key
    # derivation.
    #
    # @param [OpenSSL::PKey::EC] private_key value used by the operation.
    # @param [OpenSSL::PKey::EC] peer_public_key value used by the operation.
    # @return [String] the requested protocol value.

    def shared_secret(private_key, peer_public_key)
      result =
        private_key.dh_compute_key(
          peer_public_key.public_key
        )

      unless result.bytesize == 32
        raise OpenSSL::PKey::PKeyError,
              "expected 32-byte P-256 ECDH shared secret"
      end

      result
    end


    # Derives the 16-byte Tesla session key by hashing the 32-byte ECDH shared
    # secret with SHA-1 and taking the first 16 bytes, matching the protocol
    # key schedule.
    #
    # @param [String] shared_secret value used by the operation.
    # @return [String] the requested protocol value.

    def derive_session_key(shared_secret)
      unless shared_secret.bytesize == 32
        raise ArgumentError,
              "expected 32-byte P-256 shared secret"
      end

      OpenSSL::Digest::SHA1.digest(
        shared_secret
      )[0, 16]
    end

    # Combines ECDH and the Tesla session-key derivation into one operation for
    # a local private key and peer public key.
    #
    # @param [OpenSSL::PKey::EC] private_key value used by the operation.
    # @param [OpenSSL::PKey::EC] peer_public_key value used by the operation.
    # @return [String] the requested protocol value.

    def session_key(private_key, peer_public_key)
      derive_session_key(
        shared_secret(
          private_key,
          peer_public_key
        )
      )
    end

    # Computes an HMAC-SHA256 digest over binary protocol data using the
    # supplied key.
    #
    # @param [OpenSSL::PKey::EC] key value used by the operation.
    # @param [String] data value used by the operation.
    # @return [String] the command result or constructed protocol value.

    def hmac_sha256(key, data)
      OpenSSL::HMAC.digest(
        "SHA256",
        key,
        data
      )
    end


    # Derives the HMAC key used to authenticate SessionInfo data from the
    # established session key.
    #
    # @param [String] session_key value used by the operation.
    # @return [String] the command result or constructed protocol value.

    def session_info_key(session_key)
      hmac_sha256(
        session_key,
        "session info"
      )
    end


    # Derives the HMAC key used to authenticate signed commands from the
    # established session key.
    #
    # @param [String] session_key value used by the operation.
    # @return [String] the command result or constructed protocol value.

    def command_key(session_key)
      hmac_sha256(
        session_key,
        "authenticated command"
      )
    end


    # Compares two byte strings without returning early based on differing byte
    # values. It first requires equal lengths, then accumulates all byte
    # differences to avoid a data-dependent comparison exit.
    #
    # @param [String] a value used by the operation.
    # @param [String] b value used by the operation.
    # @return [Boolean] the command result or constructed protocol value.

    def secure_compare(a, b)
      return false unless a.bytesize == b.bytesize

      result = 0

      a.bytes.zip(b.bytes) do |x, y|
        result |= x ^ y
      end

      result == 0
    end

    #------------------------------------------------------------------------

    AES_GCM_KEY_LENGTH = 16
    AES_GCM_IV_LENGTH  = 12
    AES_GCM_TAG_LENGTH = 16

    # Authenticates and decrypts an AES-128-GCM response. The authentication
    # tag is installed before finalization so a bad tag raises an OpenSSL
    # cipher error rather than returning unauthenticated plaintext.
    #
    # @return [String] the command result or constructed protocol value.

    def self.aes_gcm_decrypt(
      key:,
      iv:,
      ciphertext:,
      tag:,
      aad: nil
    )
      raise ArgumentError, "AES-GCM key must be 16 bytes" unless
        key.bytesize == AES_GCM_KEY_LENGTH

      raise ArgumentError, "AES-GCM IV must be 12 bytes" unless
        iv.bytesize == AES_GCM_IV_LENGTH

      raise ArgumentError, "AES-GCM tag must be 16 bytes" unless
        tag.bytesize == AES_GCM_TAG_LENGTH

      cipher = OpenSSL::Cipher.new("aes-128-gcm")
      cipher.decrypt

      cipher.key = key
      cipher.iv = iv
      cipher.auth_tag = tag

      cipher.auth_data = aad || +"".b

      plaintext =
        if ciphertext.empty?
          cipher.final
        else
          cipher.update(ciphertext) + cipher.final
        end

      plaintext
    end

    # Returns the raw SHA-256 digest of the supplied binary data.
    #
    # @param [String] data value used by the operation.
    # @return [String] the command result or constructed protocol value.

    def self.sha256(data)
      Digest::SHA256.digest(data)
    end

    #------------------------------------------------------------------------

  end
end
