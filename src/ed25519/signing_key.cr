require "./verify_key"

class Ed25519::SigningKey
  def initialize(key_bytes : Bytes = Random::Secure.hex(32).hexbytes)
    if key_bytes.size == 64
      # assume this key is from libsodium or similar, where the private key includes the public key
      @key_bytes = key_bytes[0..31]
    else
      @key_bytes = key_bytes
    end
  end

  getter key_bytes : Bytes
  getter verify_key : VerifyKey { VerifyKey.new(Ed25519.get_public_key(@key_bytes)) }

  def to_slice
    @key_bytes
  end

  def key_size
    @key_bytes.size
  end

  def sign(message : Bytes | String) : Bytes
    bytes = message.to_slice
    Ed25519.sign bytes, @key_bytes
  end
end
