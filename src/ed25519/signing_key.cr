require "./verify_key"

class Ed25519::SigningKey
  def initialize(seed : UInt64 = rand(UInt64::MAX), key_size : Int32 = 32)
    @seed = seed
    random = Random.new(seed)
    @key_bytes = random.random_bytes(key_size)
  end

  def initialize(@key_bytes : Bytes)
  end

  getter seed : UInt64? = nil
  getter key_bytes : Bytes
  getter verify_key : VerifyKey { VerifyKey.new(Ed25519.getPublicKey(@key_bytes)) }

  def key_size
    @key_bytes.size
  end

  def sign(message : Bytes | String) : Bytes
    bytes = message.to_slice
    Ed25519.sign bytes, @key_bytes
  end
end
