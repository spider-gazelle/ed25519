# Extended Point works in extended coordinates: (x, y, z, t) ∋ (x=x/z, y=y/z, t=xy).
# Default Point works in affine coordinates: (x, y)
# https://en.wikipedia.org/wiki/Twisted_Edwards_curve#Extended_coordinates
class Ed25519::ExtendedPoint
  BASE = ExtendedPoint.new(Curve::Gx, Curve::Gy, One, Ed25519.mod(Curve::Gx * Curve::Gy))
  ZERO = ExtendedPoint.new(Zero, One, One, Zero)

  def self.fromAffine(p : Point) : ExtendedPoint
    if p == Point::ZERO
      ExtendedPoint::ZERO
    else
      ExtendedPoint.new(p.x, p.y, One, Ed25519.mod(p.x * p.y))
    end
  end

  # Takes a bunch of Jacobian Points but executes only one
  # invert on all of them. invert is very slow operation,
  # so this improves performance massively.
  def self.toAffineBatch(points : Array(ExtendedPoint)) : Array(Point)
    toInv = Ed25519.invertBatch(points.map(&.z))
    points.map_with_index { |p, i| p.toAffine(toInv[i]) }
  end

  def self.normalizeZ(points : Array(ExtendedPoint)) : Array(ExtendedPoint)
    self.toAffineBatch(points).map { |p| fromAffine(p) }
  end

  property x : BigInt
  property y : BigInt
  property z : BigInt
  property t : BigInt

  def initialize(@x : BigInt, @y : BigInt, @z : BigInt, @t : BigInt)
  end

  # Compare one point to another.
  def equals(other : ExtendedPoint) : Bool
    x1, y1, z1 = @x, @y, @z
    x2, y2, z2 = other.x, other.y, other.z
    x1z2 = Ed25519.mod(x1 * z2)
    x2z1 = Ed25519.mod(x2 * z1)
    y1z2 = Ed25519.mod(y1 * z2)
    y2z1 = Ed25519.mod(y2 * z1)
    return x1z2 === x2z1 && y1z2 === y2z1
  end

  def ==(other : ExtendedPoint) : Bool
    equals(other)
  end

  # Inverses point to one corresponding to (x, -y) in Affine coordinates.
  def negate : ExtendedPoint
    return ExtendedPoint.new(Ed25519.mod(-@x), @y, @z, Ed25519.mod(-@t))
  end

  # Fast algo for doubling Extended Point when curve's a=-1.
  # http://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#doubling-dbl-2008-hwcd
  # Cost: 3M + 4S + 1*a + 7add + 1*2.
  def double : ExtendedPoint
    x1, y1, z1 = @x, @y, @z
    a = Ed25519.mod(x1 ** Ed25519::Two)
    b = Ed25519.mod(y1 ** Ed25519::Two)
    c = Ed25519.mod(Ed25519::Two * Ed25519.mod(z1 ** Ed25519::Two))
    d = Ed25519.mod(Curve::A * a)
    e = Ed25519.mod(Ed25519.mod((x1 + y1) ** Ed25519::Two) - a - b)
    g = d + b
    f = g - c
    h = d - b
    x3 = Ed25519.mod(e * f)
    y3 = Ed25519.mod(g * h)
    t3 = Ed25519.mod(e * h)
    z3 = Ed25519.mod(f * g)
    return ExtendedPoint.new(x3, y3, z3, t3)
  end

  # Fast algo for adding 2 Extended Points when curve's a=-1.
  # http://hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html#addition-add-2008-hwcd-4
  # Cost: 8M + 8add + 2*2.
  # Note: It does not check whether the `other` point is valid.
  def add(other : ExtendedPoint)
    # assertExtPoint(other)
    x1, y1, z1, t1 = @x, @y, @z, @t
    x2, y2, z2, t2 = other.x, other.y, other.z, other.t
    a = Ed25519.mod((y1 - x1) * (y2 + x2))
    b = Ed25519.mod((y1 + x1) * (y2 - x2))
    f = Ed25519.mod(b - a)
    if f === Zero
      self.double # Same point.
    else
      c = Ed25519.mod(z1 * Ed25519::Two * t2)
      d = Ed25519.mod(t1 * Ed25519::Two * z2)
      e = d + c
      g = b + a
      h = d - c
      x3 = Ed25519.mod(e * f)
      y3 = Ed25519.mod(g * h)
      t3 = Ed25519.mod(e * h)
      z3 = Ed25519.mod(f * g)
      ExtendedPoint.new(x3, y3, z3, t3)
    end
  end

  def subtract(other : ExtendedPoint) : ExtendedPoint
    return self.add(other.negate)
  end

  private def precomputeWindow(w : Int) : Array(ExtendedPoint)
    windows = 1 + 256 / w
    points : Array(ExtendedPoint) = [] of ExtendedPoint
    p : ExtendedPoint = self
    base = p
    window = 0
    while window < windows # for (window = 0 window < windows window++)
      base = p
      points.push(base)
      i = 1
      while i < 2 ** (w - 1) # for (i = 1 i < 2 ** (W - 1) i++)
        base = base.add(p)
        points.push(base)
        i += 1
      end
      p = base.double
      window += 1
    end
    return points
  end

  private def wNAF(n : BigInt, affinePoint : Point? = nil) : ExtendedPoint
    if affinePoint.nil? && self == ExtendedPoint::BASE
      affinePoint = Point::BASE
    end
    w = affinePoint.try(&._WINDOW_SIZE) || 1
    raise ArgumentError.new("Point#wNAF: Invalid precomputation window, must be power of 2") if 256 % w != 0

    precomputes : Array(ExtendedPoint) = if affinePoint && (points = Ed25519::PointPrecomputes[affinePoint]?)
      points
    else
      points = precomputeWindow(w)
      if affinePoint && w != 1
        points = ExtendedPoint.normalizeZ(points)
        Ed25519::PointPrecomputes[affinePoint] = points
      end
      points
    end

    p = ExtendedPoint::ZERO
    f = ExtendedPoint::ZERO

    windows = 1 + 256 / w
    windowSize = 2 ** (w - 1)
    mask = BigInt.new(2 ** w - 1) # Create mask with W ones: 0b1111 for W=4 etc.
    maxNumber = 2 ** w
    shiftBy = BigInt.new(w)

    window = 0
    while window < windows # for (window = 0 window < windows window++)
      offset = window * windowSize
      # Extract W bits.
      wbits = n & mask

      # Shift number by W bits.
      n >>= shiftBy

      # If the bits are bigger than max size, we'll split those.
      # +224 => 256 - 32
      if wbits > windowSize
        wbits -= maxNumber
        n += One
      end

      # Check if we're onto Zero point.
      # Add random point inside current window to f.
      if wbits == 0
        pr = precomputes[offset]
        if window % 2 != 0
          pr = pr.negate
        end
        f = f.add(pr)
      else
        cached = precomputes[offset + wbits.abs - 1]
        if wbits < 0
          cached = cached.negate
        end
        p = p.add(cached)
      end
      window += 1
    end
    ExtendedPoint.normalizeZ([p, f])[0]
  end

  # Constant time multiplication.
  # Uses wNAF method. Windowed method may be 10% faster,
  # but takes 2x longer to generate and consumes 2x memory.
  def multiply(scalar : Int, affinePoint : Point?) : ExtendedPoint
    wNAF(Ed25519.normalizeScalar(scalar, Curve::L), affinePoint)
  end

  # Non-constant-time multiplication. Uses double-and-add algorithm.
  # It's faster, but should only be used when you don't care about
  # an exposed private key e.g. sig verification.
  # Allows scalar bigger than curve order, but less than 2^256
  def multiplyUnsafe(scalar : Int) : ExtendedPoint
    n = Ed25519.normalizeScalar(scalar, Curve::L, false)
    g = ExtendedPoint::BASE
    p0 = ExtendedPoint::ZERO
    if n == Zero
      p0
    elsif self.equals(p0) || n === One
      self
    elsif self.equals(g)
      wNAF(n)
    else
      p = p0
      d : ExtendedPoint = self
      while n > Zero
        if n & One != 0
          p = p.add(d)
        end
        d = d.double
        n >>= One
      end
      p
    end
  end

  def isSmallOrder : Bool
    self.multiplyUnsafe(Curve::H).equals(ExtendedPoint::ZERO)
  end

  def isTorsionFree : Bool
    self.multiplyUnsafe(Curve::L).equals(ExtendedPoint::ZERO)
  end

  # Converts Extended point to default (x, y) coordinates.
  # Can accept precomputed Z^-1 - for example, from invertBatch.
  def toAffine(invZ : BigInt = Ed25519.invert(@z)) : Point
    x, y, z = @x, @y, @z
    ax = Ed25519.mod(x * invZ)
    ay = Ed25519.mod(y * invZ)
    zz = Ed25519.mod(z * invZ)
    raise Exception.new("invZ was invalid") if zz != One
    Point.new(ax, ay)
  end
end
