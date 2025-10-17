# Extended Point works in extended coordinates: (x, y, z, t) ∋ (x=x/z, y=y/z, t=xy).
# Default Point works in affine coordinates: (x, y)
# https://en.wikipedia.org/wiki/Twisted_Edwards_curve#Extended_coordinates
class Ed25519::ExtendedPoint
  BASE = ExtendedPoint.new(Curve::Gx, Curve::Gy, One, Ed25519.mod(Curve::Gx * Curve::Gy))
  ZERO = ExtendedPoint.new(Zero, One, One, Zero)

  def self.from_affine(p : Point) : ExtendedPoint
    if p == Point::ZERO
      ExtendedPoint::ZERO
    else
      ExtendedPoint.new(p.x, p.y, One, Ed25519.mod(p.x * p.y))
    end
  end

  # Takes a bunch of Jacobian Points but executes only one
  # invert on all of them. invert is very slow operation,
  # so this improves performance massively.
  def self.to_affine_batch(points : Array(ExtendedPoint)) : Array(Point)
    to_inv = Ed25519.invert_batch(points.map(&.z))
    points.map_with_index { |point, index| point.to_affine(to_inv[index]) }
  end

  def self.normalize_z(points : Array(ExtendedPoint)) : Array(ExtendedPoint)
    self.to_affine_batch(points).map { |point| from_affine(point) }
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
    x1z2 === x2z1 && y1z2 === y2z1
  end

  def ==(other : ExtendedPoint) : Bool
    equals(other)
  end

  # Inverses point to one corresponding to (x, -y) in Affine coordinates.
  def negate : ExtendedPoint
    ExtendedPoint.new(Ed25519.mod(-@x), @y, @z, Ed25519.mod(-@t))
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
    ExtendedPoint.new(x3, y3, z3, t3)
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
    self.add(other.negate)
  end

  private def precompute_window(w : Int) : Array(ExtendedPoint)
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
    points
  end

  # ameba:disable Metrics/CyclomaticComplexity
  private def w_naf(n : BigInt, affine_point : Point? = nil) : ExtendedPoint
    if affine_point.nil? && self == ExtendedPoint::BASE
      affine_point = Point::BASE
    end
    w = affine_point.try(&._window_size) || 1
    raise VerifyError.new("Point#w_naf: Invalid precomputation window, must be power of 2") if 256 % w != 0

    precomputes : Array(ExtendedPoint) = if affine_point && (points = Ed25519::PointPrecomputes[affine_point]?)
      points
    else
      points = precompute_window(w)
      if affine_point && w != 1
        points = ExtendedPoint.normalize_z(points)
        Ed25519::PointPrecomputes[affine_point] = points
      end
      points
    end

    p = ExtendedPoint::ZERO
    f = ExtendedPoint::ZERO

    windows = 1 + 256 / w
    window_size = 2 ** (w - 1)
    mask = BigInt.new(2 ** w - 1) # Create mask with W ones: 0b1111 for W=4 etc.
    max_number = 2 ** w
    shift_by = BigInt.new(w)

    window = 0
    while window < windows # for (window = 0 window < windows window++)
      offset = window * window_size
      # Extract W bits.
      wbits = n & mask

      # Shift number by W bits.
      n >>= shift_by

      # If the bits are bigger than max size, we'll split those.
      # +224 => 256 - 32
      if wbits > window_size
        wbits -= max_number
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
    ExtendedPoint.normalize_z([p, f])[0]
  end

  # Constant time multiplication.
  # Uses w_naf method. Windowed method may be 10% faster,
  # but takes 2x longer to generate and consumes 2x memory.
  def multiply(scalar : Int, affine_point : Point?) : ExtendedPoint
    w_naf(Ed25519.normalize_scalar(scalar, Curve::L), affine_point)
  end

  # Non-constant-time multiplication. Uses double-and-add algorithm.
  # It's faster, but should only be used when you don't care about
  # an exposed private key e.g. sig verification.
  # Allows scalar bigger than curve order, but less than 2^256
  def multiply_unsafe(scalar : Int) : ExtendedPoint
    n = Ed25519.normalize_scalar(scalar, Curve::L, false)
    g = ExtendedPoint::BASE
    p0 = ExtendedPoint::ZERO
    if n == Zero
      p0
    elsif self.equals(p0) || n === One
      self
    elsif self.equals(g)
      w_naf(n)
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

  def small_order? : Bool
    self.multiply_unsafe(Curve::H).equals(ExtendedPoint::ZERO)
  end

  def torsion_free? : Bool
    self.multiply_unsafe(Curve::L).equals(ExtendedPoint::ZERO)
  end

  # Converts Extended point to default (x, y) coordinates.
  # Can accept precomputed Z^-1 - for example, from invert_batch.
  def to_affine(inv_z : BigInt = Ed25519.invert(@z)) : Point
    x, y, z = @x, @y, @z
    ax = Ed25519.mod(x * inv_z)
    ay = Ed25519.mod(y * inv_z)
    zz = Ed25519.mod(z * inv_z)
    raise VerifyError.new("inv_z was invalid") if zz != One
    Point.new(ax, ay)
  end
end
