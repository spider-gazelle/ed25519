module Ed25519::Curve25519
  BASE_POINT_U = "0900000000000000000000000000000000000000000000000000000000000000"

  # crypto_scalarmult aka get_shared_secret
  def self.scalar_mult(private_key : Hex, public_key : Hex) : Bytes
    u = Ed25519.decode_u_coordinate(public_key)
    p = Ed25519.decode_scalar_25519(private_key)
    pu = Ed25519.montgomery_ladder(u, p)
    # The result was not contributory
    # https://cr.yp.to/ecdh.html#validate
    raise VerifyError.new("Invalid private or public key received") if pu == Zero
    Ed25519.encode_u_coordinate(pu)
  end

  # crypto_scalarmult_base aka get_public_key
  def self.scalar_mult_base(private_key : Hex) : Bytes
    scalar_mult(private_key, BASE_POINT_U)
  end
end
