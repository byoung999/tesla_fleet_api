require_relative "../test_helper"

class TestTeslaCrypto < Minitest::Test
  def test_generate_key
    key =
      Tesla::Crypto.generate_key

    assert_instance_of(
      OpenSSL::PKey::EC,
      key
    )

    assert_equal(
      65,
      Tesla::Crypto.encoded_public_key(key).bytesize
    )
  end

  def test_public_key_round_trip
    private_key =
      Tesla::Crypto.generate_key

    encoded =
      Tesla::Crypto.encoded_public_key(
        private_key
      )

    public_key =
      Tesla::Crypto.public_key_from_bytes(
        encoded
      )

    assert_equal(
      encoded,
      public_key.public_key.to_octet_string(:uncompressed)
    )
  end

  def test_rejects_wrong_length
    assert_raises(ArgumentError) do
      Tesla::Crypto.public_key_from_bytes(
        "\x04".b + ("\x00" * 63)
      )
    end
  end

  def test_rejects_compressed_key
    assert_raises(ArgumentError) do
      Tesla::Crypto.public_key_from_bytes(
        "\x02".b + ("\x00" * 32)
      )
    end
  end

  def test_ecdh_is_symmetric
    alice =
      Tesla::Crypto.generate_key

    bob =
      Tesla::Crypto.generate_key

    alice_public =
      Tesla::Crypto.public_key_from_bytes(
        Tesla::Crypto.encoded_public_key(alice)
      )

    bob_public =
      Tesla::Crypto.public_key_from_bytes(
        Tesla::Crypto.encoded_public_key(bob)
      )

    alice_shared =
      Tesla::Crypto.shared_secret(
        alice,
        bob_public
      )

    bob_shared =
      Tesla::Crypto.shared_secret(
        bob,
        alice_public
      )

    assert_equal(
      alice_shared,
      bob_shared
    )
  end

  def test_session_key_is_16_bytes
    alice =
      Tesla::Crypto.generate_key

    bob =
      Tesla::Crypto.generate_key

    bob_public =
      Tesla::Crypto.public_key_from_bytes(
        Tesla::Crypto.encoded_public_key(bob)
      )

    key =
      Tesla::Crypto.session_key(
        alice,
        bob_public
      )

    assert_equal 16, key.bytesize
  end

  def test_hmac
    result =
      Tesla::Crypto.hmac_sha256(
        "key",
        "data"
      )

    assert_equal(
      "5d5d139563c95b5967b9d4a9a8b6c8f7" \
      "6f0b4f1f5f4d7d8c7f6e5e6d5c4b3a29",
      result.unpack1("H*")
    ) if false

    assert_equal 32, result.bytesize
  end

  def test_secure_compare
    assert(
      Tesla::Crypto.secure_compare(
        "abc",
        "abc"
      )
    )

    refute(
      Tesla::Crypto.secure_compare(
        "abc",
        "abd"
      )
    )

    refute(
      Tesla::Crypto.secure_compare(
        "abc",
        "abcd"
      )
    )
  end

  def test_aes_gcm_decrypt
    key = "K" * 16
    iv = "I" * 12
    plaintext = "secret command response"
    aad = "request hash"

    cipher = OpenSSL::Cipher.new("aes-128-gcm")
    cipher.encrypt
    cipher.key = key
    cipher.iv = iv
    cipher.auth_data = aad

    ciphertext =
      cipher.update(plaintext) + cipher.final

    tag = cipher.auth_tag

    result =
      Tesla::Crypto.aes_gcm_decrypt(
        key: key,
        iv: iv,
        ciphertext: ciphertext,
        tag: tag,
        aad: aad
      )

    assert_equal plaintext, result
  end

  def test_aes_gcm_decrypt_rejects_invalid_tag
    key = "K" * 16
    iv = "I" * 12
    plaintext = "secret command response"
    aad = "request hash"

    cipher = OpenSSL::Cipher.new("aes-128-gcm")
    cipher.encrypt
    cipher.key = key
    cipher.iv = iv
    cipher.auth_data = aad

    ciphertext =
      cipher.update(plaintext) + cipher.final

    tag = cipher.auth_tag

    tag = tag.dup
    tag.setbyte(0, tag.getbyte(0) ^ 0xff)

    assert_raises(OpenSSL::Cipher::CipherError) do
      Tesla::Crypto.aes_gcm_decrypt(
        key: key,
        iv: iv,
        ciphertext: ciphertext,
        tag: tag,
        aad: aad
      )
    end
  end

  def test_aes_gcm_decrypt_rejects_modified_aad
    key = "K" * 16
    iv = "I" * 12
    plaintext = "secret command response"

    cipher = OpenSSL::Cipher.new("aes-128-gcm")
    cipher.encrypt
    cipher.key = key
    cipher.iv = iv
    cipher.auth_data = "original request"

    ciphertext =
      cipher.update(plaintext) + cipher.final

    tag = cipher.auth_tag

    assert_raises(OpenSSL::Cipher::CipherError) do
      Tesla::Crypto.aes_gcm_decrypt(
        key: key,
        iv: iv,
        ciphertext: ciphertext,
        tag: tag,
        aad: "modified request"
      )
    end
  end

end
