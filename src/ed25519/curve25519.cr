module Ed25519::Curve25519
  BASE_POINT_U = "0900000000000000000000000000000000000000000000000000000000000000"

  # crypto_scalarmult aka getSharedSecret
  def self.scalarMult(privateKey : Hex, publicKey : Hex) : Bytes
    u = Ed25519.decodeUCoordinate(publicKey)
    p = Ed25519.decodeScalar25519(privateKey)
    pu = Ed25519.montgomeryLadder(u, p)
    # The result was not contributory
    # https://cr.yp.to/ecdh.html#validate
    raise Exception.new("Invalid private or public key received") if pu == Zero
    Ed25519.encodeUCoordinate(pu)
  end

  # crypto_scalarmult_base aka getPublicKey
  def self.scalarMultBase(privateKey : Hex) : Bytes
    scalarMult(privateKey, BASE_POINT_U)
  end
end
