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
    property _WINDOW_SIZE : Int32
    property x : BigInt
    property y : BigInt

    def initialize(@x : BigInt, @y : BigInt)
      @_WINDOW_SIZE = 8
    end

    # Note: This method is not in the original typescript implementation.
    # This method only exists to retain the WeakMap semantics that were encoded in the original implementation
    # through the use of WeakMap(Point, Array(ExtendedPoint)) in typescript.
    def finialize
      Ed25519::PointPrecomputes.delete(self)
    end

    # "Private method", don't use it directly.
    def _setWindowSize(windowSize : Int32)
      @_WINDOW_SIZE = windowSize
      Ed25519::PointPrecomputes.delete(self)
    end

    # Converts hash string or Bytes to Point.
    # Uses algo from RFC8032 5.1.3.
    def self.fromHex(hex : Hex, strict = true)
      hex_bytes = Ed25519.ensureBytes(hex, 32)

      # 1.  First, interpret the string as an integer in little-endian
      # representation. Bit 255 of this number is the least significant
      # bit of the x-coordinate and denote this value x_0.  The
      # y-coordinate is recovered simply by clearing this bit.  If the
      # resulting value is >= p, decoding fails.
      normed = hex_bytes.clone
      normed[31] = hex_bytes[31] & ~0x80
      y = Ed25519.bytesToNumberLE(normed)

      raise Exception.new("Expected 0 < hex < P") if strict && y >= Curve::P
      raise Exception.new("Expected 0 < hex < 2**256") if !strict && y >= MAX_256B

      # 2.  To recover the x-coordinate, the curve equation implies
      # x² = (y² - 1) / (d y² + 1) (mod p).  The denominator is always
      # non-zero mod p.  Let u = y² - 1 and v = d y² + 1.
      y2 = Ed25519.mod(y * y)
      u = Ed25519.mod(y2 - One)
      v = Ed25519.mod(Curve::D * y2 + One)
      pair = Ed25519.uvRatio(u, v)
      isValid = pair[:isValid]
      x = pair[:value]
      raise Exception.new("Point.fromHex: invalid y coordinate") unless isValid

      # 4.  Finally, use the x_0 bit to select the right square root.  If
      # x = 0, and x_0 = 1, decoding fails.  Otherwise, if x_0 != x mod
      # 2, set x <-- p - x.  Return the decoded point (x,y).
      isXOdd = (x & One) == One
      isLastByteOdd = (hex_bytes[31] & 0x80) != 0
      if isLastByteOdd != isXOdd
        x = Ed25519.mod(-x)
      end

      Point.new(x, y)
    end

    def self.fromPrivateKey(privateKey : PrivKey)
      getExtendedPublicKey(privateKey).point
    end

    # There can always be only two x values (x, -x) for any y
    # When compressing point, it's enough to only store its y coordinate
    # and use the last byte to encode sign of x.
    def toRawBytes : Bytes
      bytes = Ed25519.numberTo32BytesLE(@y)
      bytes[31] |= (@x & One == One ? 0x80 : 0)
      bytes
    end

    # Same as toRawBytes, but returns string.
    def toHex : String
      Ed25519.bytesToHex(self.toRawBytes)
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
    def toX25519 : Bytes
      u = Ed25519.mod((One + @y) * Ed25519.invert(One - @y))
      return Ed25519.numberTo32BytesLE(u)
    end

    def isTorsionFree : Bool
      return ExtendedPoint.fromAffine(self).isTorsionFree
    end

    def equals(other : Point) : Bool
      return @x === other.x && @y === other.y
    end

    def ==(other : Point) : Bool
      equals(other)
    end

    def negate
      return Point.new(Ed25519.mod(-@x), @y)
    end

    def add(other : Point)
      return ExtendedPoint.fromAffine(self).add(ExtendedPoint.fromAffine(other)).toAffine
    end

    def subtract(other : Point)
      return self.add(other.negate)
    end

    # **
    # Constant time multiplication.
    # @param scalar Big-Endian number
    # @returns new point
    # /
    def multiply(scalar : Int) : Point
      ExtendedPoint.fromAffine(self).multiply(scalar, self).toAffine
    end
  end
end
