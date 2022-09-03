require "./signing_key"

class Ed25519::VerifyKey
  def initialize(@key_bytes : Bytes)
  end

  def new(signing_key : SigningKey)
    signing_key.verify_key
  end

  getter key_bytes : Bytes

  def to_slice
    @key_bytes
  end

  def verify(signature : Bytes, message : Bytes | String) : Bool
    bytes = message.to_slice
    Ed25519.verify(signature, bytes, @key_bytes)
  end

  def verify!(signature : Bytes, message : Bytes | String)
    raise VerifyError.new("signature verification failed!") unless verify(signature, message)
  end
end
