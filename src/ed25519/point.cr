module Ed25519
  # Stores precomputed values for points.
  PointPrecomputes = Hash(Point, Array(ExtendedPoint)).new # Todo: This should be a WeakMap, to retain the same semantics as the original implementation in typescript

  # **
  # Default Point works in affine coordinates: (x, y)
  # /
  class Point
    # Base point aka generator
    # public_key = Point::BASE * private_key
    BASE = Point.new(Ed25519::Curve::Gx, Ed25519::Curve::Gy)
    # Identity point aka point at infinity
    # point = point + zero_point
    ZERO = Point.new(Zero, One)

    # We calculate precomputes for elliptic curve point multiplication
    # using windowed method. This specifies window size and
    # stores precomputed values. Usually only base point would be precomputed.
    property _window_size : Int32
    property x : BigInt
    property y : BigInt

    def initialize(@x : BigInt, @y : BigInt)
      @_window_size = 8
    end

    # Note: This method is not in the original typescript implementation.
    # This method only exists to retain the WeakMap semantics that were encoded in the original implementation
    # through the use of WeakMap(Point, Array(ExtendedPoint)) in typescript.
    def finialize
      Ed25519::PointPrecomputes.delete(self)
    end

    # "Private method", don't use it directly.
    def _set_window_size(window_size : Int32)
      @_window_size = window_size
      Ed25519::PointPrecomputes.delete(self)
    end

    # Converts hash string or Bytes to Point.
    # Uses algo from RFC8032 5.1.3.
    def self.from_hex(hex : Hex, strict = true)
      hex_bytes = Ed25519.ensure_bytes(hex, 32)

      # 1.  First, interpret the string as an integer in little-endian
      # representation. Bit 255 of this number is the least significant
      # bit of the x-coordinate and denote this value x_0.  The
      # y-coordinate is recovered simply by clearing this bit.  If the
      # resulting value is >= p, decoding fails.
      normed = hex_bytes.clone
      normed[31] = hex_bytes[31] & ~0x80
      y = Ed25519.bytes_to_number_le(normed)

      raise VerifyError.new("Expected 0 < hex < P") if strict && y >= Curve::P
      raise VerifyError.new("Expected 0 < hex < 2**256") if !strict && y >= MAX_256B

      # 2.  To recover the x-coordinate, the curve equation implies
      # x² = (y² - 1) / (d y² + 1) (mod p).  The denominator is always
      # non-zero mod p.  Let u = y² - 1 and v = d y² + 1.
      y2 = Ed25519.mod(y * y)
      u = Ed25519.mod(y2 - One)
      v = Ed25519.mod(Curve::D * y2 + One)
      pair = Ed25519.uv_ratio(u, v)
      is_valid = pair[:is_valid]
      x = pair[:value]
      raise VerifyError.new("Invalid Point y coordinate") unless is_valid

      # 4.  Finally, use the x_0 bit to select the right square root.  If
      # x = 0, and x_0 = 1, decoding fails.  Otherwise, if x_0 != x mod
      # 2, set x <-- p - x.  Return the decoded point (x,y).
      is_x_odd = (x & One) == One
      is_last_byte_odd = (hex_bytes[31] & 0x80) != 0
      if is_last_byte_odd != is_x_odd
        x = Ed25519.mod(-x)
      end

      Point.new(x, y)
    end

    def self.from_private_key(private_key : PrivKey)
      get_extended_public_key(private_key).point
    end

    # There can always be only two x values (x, -x) for any y
    # When compressing point, it's enough to only store its y coordinate
    # and use the last byte to encode sign of x.
    def to_raw_bytes : Bytes
      bytes = Ed25519.number_to_32_bytes_le(@y)
      bytes[31] |= (@x & One == One ? 0x80 : 0)
      bytes
    end

    # Same as to_raw_bytes, but returns string.
    def to_hex : String
      Ed25519.bytes_to_hex(self.to_raw_bytes)
    end

    # **
    # Converts to Montgomery aka x coordinate of curve25519.
    # We don't have fromX25519, because we don't know sign.
    #
    # ```
    # u, v: curve25519 coordinates
    # x, y: ed25519 coordinates
    # (u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)
    # (x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))
    # ```
    # https://blog.filippo.io/using-ed25519-keys-for-encryption
    # @returns u coordinate of curve25519 point
    # /
    def to_x25519 : Bytes
      u = Ed25519.mod((One + @y) * Ed25519.invert(One - @y))
      Ed25519.number_to_32_bytes_le(u)
    end

    def torsion_free? : Bool
      ExtendedPoint.from_affine(self).torsion_free?
    end

    def equals(other : Point) : Bool
      @x === other.x && @y === other.y
    end

    def ==(other : Point) : Bool
      equals(other)
    end

    def negate
      Point.new(Ed25519.mod(-@x), @y)
    end

    def add(other : Point)
      ExtendedPoint.from_affine(self).add(ExtendedPoint.from_affine(other)).to_affine
    end

    def subtract(other : Point)
      self.add(other.negate)
    end

    # **
    # Constant time multiplication.
    # @param scalar Big-Endian number
    # @returns new point
    # /
    def multiply(scalar : Int) : Point
      ExtendedPoint.from_affine(self).multiply(scalar, self).to_affine
    end
  end
end
