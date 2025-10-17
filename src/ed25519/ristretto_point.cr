# **
# Each ed25519/ExtendedPoint has 8 different equivalent points. This can be
# a source of bugs for protocols like ring signatures. Ristretto was created to solve this.
# Ristretto point operates in X:Y:Z:T extended coordinates like ExtendedPoint,
# but it should work in its own namespace: do not combine those two.
# https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-ristretto255-decaf448
# /
class Ed25519::RistrettoPoint
  BASE = RistrettoPoint.new(ExtendedPoint::BASE)
  ZERO = RistrettoPoint.new(ExtendedPoint::ZERO)

  property ep : ExtendedPoint

  # Private property to discourage combining ExtendedPoint + RistrettoPoint
  # Always use Ristretto encoding/decoding instead.
  def initialize(@ep : ExtendedPoint)
  end

  # Computes Elligator map for Ristretto
  # https://ristretto.group/formulas/elligator.html
  private def self.calc_elligator_ristretto_map(r0 : BigInt) : ExtendedPoint
    r = Ed25519.mod(SQRT_M1 * r0 * r0)                              # 1
    ns = Ed25519.mod((r + One) * ONE_MINUS_D_SQ)                    # 2
    c = BigInt.new(-1)                                              # 3
    d = Ed25519.mod((c - Curve::D * r) * Ed25519.mod(r + Curve::D)) # 4
    pair = uv_ratio(ns, d)                                          # 5
    ns_d_is_sq = pair[:is_valid]
    s = pair.value
    s_ = Ed25519.mod(s * r0) # 6
    s_ = Ed25519.mod(-s_) unless ed_is_negative(s_)
    s = s_ unless ns_d_is_sq                             # 7
    c = r unless ns_d_is_sq                              # 8
    nt = Ed25519.mod(c * (r - One) * D_MINUS_ONE_SQ - d) # 9
    s2 = s * s
    w0 = Ed25519.mod((s + s) * d)            # 10
    w1 = Ed25519.mod(nt * SQRT_AD_MINUS_ONE) # 11
    w2 = Ed25519.mod(One - s2)               # 12
    w3 = Ed25519.mod(One + s2)               # 13
    ExtendedPoint.new(Ed25519.mod(w0 * w3), Ed25519.mod(w2 * w1), Ed25519.mod(w1 * w3), Ed25519.mod(w0 * w2))
  end

  # **
  # Takes uniform output of 64-bit hash function like sha512 and converts it to `RistrettoPoint`.
  # The hash-to-group operation applies Elligator twice and adds the results.
  # **Note:** this is one-way map, there is no conversion from point to hash.
  # https://ristretto.group/formulas/elligator.html
  # @param hex 64-bit output of a hash function
  # /
  def self.hash_to_curve(hex : Hex) : RistrettoPoint
    hex = ensure_bytes(hex, 64)
    r1 = bytes_255_to_number_le(hex.slice(0, 32))
    r1_ = self.calc_elligator_ristretto_map(r1)
    r2 = bytes_255_to_number_le(hex.slice(32, 64))
    r2_ = self.calc_elligator_ristretto_map(r2)
    RistrettoPoint.new(r1_.add(r2_))
  end

  # **
  # Converts ristretto-encoded string to ristretto point.
  # https://ristretto.group/formulas/decoding.html
  # @param hex Ristretto-encoded 32 bytes. Not every 32-byte string is valid ristretto encoding
  # /
  def self.from_hex(hex : Hex) : RistrettoPoint
    hex = ensure_bytes(hex, 32)
    emsg = "RistrettoPoint.from_hex: the hex is not valid encoding of RistrettoPoint"
    s = bytes_255_to_number_le(hex)
    # 1. Check that s_bytes is the canonical encoding of a field element, or else abort.
    # 3. Check that s is non-negative, or else abort
    raise VerifyError.new(emsg) if !equal_bytes(number_to_32_bytes_le(s), hex) || ed_is_negative(s)
    s2 = Ed25519.mod(s * s)
    u1 = Ed25519.mod(One + Curve::A * s2) # 4 (a is -1)
    u2 = Ed25519.mod(One - Curve::A * s2) # 5
    u1_2 = Ed25519.mod(u1 * u1)
    u2_2 = Ed25519.mod(u2 * u2)
    v = Ed25519.mod(Curve::A * Curve::D * u1_2 - u2_2) # 6
    pair = invert_sqrt(Ed25519.mod(v * u2_2))          # 7
    i = pair.value
    dx = Ed25519.mod(i * u2)                 # 8
    dy = Ed25519.mod(i * dx * v)             # 9
    x = Ed25519.mod((s + s) * dx)            # 10
    x = Ed25519.mod(-x) if ed_is_negative(x) # 10
    y = Ed25519.mod(u1 * dy)                 # 11
    t = Ed25519.mod(x * y)                   # 12
    raise VerifyError.new(emsg) if !pair.is_valid || ed_is_negative(t) || y == Zero
    RistrettoPoint.new(ExtendedPoint.new(x, y, One, t))
  end

  # **
  # Encodes ristretto point to Bytes.
  # https ://ristretto.group/formulas/encoding.html
  # /
  def to_raw_bytes : Bytes
    x, y, z, t = @ep.x, @ep.y, @ep.z, @ep.t
    u1 = Ed25519.mod(Ed25519.mod(z + y) * Ed25519.mod(z - y)) # 1
    u2 = Ed25519.mod(x * y)                                   # 2
    # Square root always exists
    pair = invert_sqrt(Ed25519.mod(u1 * u2 ** Ed25519::Two)) # 3
    invsqrt = pair.value
    d1 = Ed25519.mod(invsqrt * u1)   # 4
    d2 = Ed25519.mod(invsqrt * u2)   # 5
    z_inv = Ed25519.mod(d1 * d2 * t) # 6
    d : BigInt = BigInt.new(0)       # 7
    if ed_is_negative(t * z_inv)
      _x = Ed25519.mod(y * SQRT_M1)
      _y = Ed25519.mod(x * SQRT_M1)
      x = _x
      y = _y
      d = Ed25519.mod(d1 * INVSQRT_A_MINUS_D)
    else
      d = d2 # 8
    end
    y = Ed25519.mod(-y) if ed_is_negative(x * z_inv) # 9
    s = Ed25519.mod((z - y) * d)                     # 10 (check footer's note, no sqrt(-a))
    s = Ed25519.mod(-s) if ed_is_negative(s)
    number_to_32_bytes_le(s) # 11
  end

  def to_hex : String
    bytes_to_hex(self.to_raw_bytes)
  end

  def to_string : String
    self.to_hex
  end

  # Compare one point to another.
  def equals(other : RistrettoPoint) : Bool
    assert_rst_point(other)
    a = self.ep
    b = other.ep
    # (x1 * y2 == y1 * x2) | (y1 * y2 == x1 * x2)
    one = Ed25519.mod(a.x * b.y) == Ed25519.mod(a.y * b.x)
    two = Ed25519.mod(a.y * b.y) == Ed25519.mod(a.x * b.x)
    one || two
  end

  def ==(other : RistrettoPoint) : Bool
    equals(other)
  end

  def add(other : RistrettoPoint) : RistrettoPoint
    assert_rst_point(other)
    RistrettoPoint.new(self.ep.add(other.ep))
  end

  def subtract(other : RistrettoPoint) : RistrettoPoint
    assert_rst_point(other)
    RistrettoPoint.new(self.ep.subtract(other.ep))
  end

  def multiply(scalar : Int) : RistrettoPoint
    RistrettoPoint.new(self.ep.multiply(scalar))
  end

  def multiply_unsafe(scalar : Int) : RistrettoPoint
    RistrettoPoint.new(self.ep.multiply_unsafe(scalar))
  end
end
