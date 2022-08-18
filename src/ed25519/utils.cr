module Ed25519::Utils
  extend self

  # The 8-torsion subgroup ℰ8.
  # Those are "buggy" points, if you multiply them by 8, you'll receive Point::ZERO.
  # Ported from curve25519-dalek.
  TORSION_SUBGROUP = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  ] of String

  # **
  # Can take 40 or more bytes of uniform input e.g. from CSPRNG or KDF
  # and convert them into private scalar, with the modulo bias being neglible.
  # As per FIPS 186 B.1.1.
  # @param hash hash output from sha512, or a similar function
  # @returns valid private scalar
  # /
  def hash_to_private_scalar(hash : Hex) : BigInt
    hash = ensure_bytes(hash)
    raise VerifyError.new("Expected 40-1024 bytes of private key as per FIPS 186") if hash.size < 40 || hash.size > 1024
    num = Ed25519.mod(bytes_to_number_le(hash), Curve::L)
    # This should never happen
    raise VerifyError.new("Invalid private key") if num === Zero || num === One
    num
  end

  def random_bytes(bytes_length : Int = 32) : Bytes
    Random::Secure.random_bytes(bytes_length)
  end

  # Note: ed25519 private keys are uniform 32-bit strings. We do not need
  # to check for modulo bias like we do in noble-secp256k1 random_private_key()
  def random_private_key : Bytes
    random_bytes(32)
  end

  def sha512(message : Bytes) : Bytes
    Digest::SHA512.digest(message)
  end

  #
  # We're doing scalar multiplication (used in get_public_key etc) with precomputed BASE_POINT
  # values. This slows down first get_public_key() by milliseconds (see Speed section),
  # but allows to speed-up subsequent get_public_key() calls up to 20x.
  # @param window_size 2, 4, 8, 16
  #
  def precompute(window_size = 8, point = Point::BASE) : Point
    cached = point.equals(Point::BASE) ? point : Point.new(point.x, point.y)
    cached._set_window_size(window_size)
    cached.multiply(Ed25519::Two)
    cached
  end
end
