require "big"
require "digest"
require "weak_ref"

module Ed25519
  extend self

  {% begin %}
    VERSION = {{ `shards version "#{__DIR__}"`.chomp.stringify.downcase }}
  {% end %}

  class VerifyError < Exception
  end

  alias Hex = Bytes | String
  alias PrivKey = Hex | BigInt
  alias PubKey = Hex | Point
  alias SigType = Hex | Signature

  Zero        = BigInt.new(0)
  One         = BigInt.new(1)
  Two         = BigInt.new(2)
  BigInt255   = BigInt.new(255)
  CURVE_ORDER = Two ** BigInt.new(252) + BigInt.new("27742317777372353535851937790883648493")

  MAX_256B = Ed25519::Two ** BigInt.new(256)

  # √(-1) aka √(a) aka 2^((p-1)/4)
  SQRT_M1 = BigInt.new("19681161376707505956807079304988542015446066515923890162744021073123829784752")
  # √d aka sqrt(-486664)
  SQRT_D = BigInt.new("6853475219497561581579357271197624642482790079785650197046958215289687604742")
  # √(ad - 1)
  SQRT_AD_MINUS_ONE = BigInt.new("25063068953384623474111414158702152701244531502492656460079210482610430750235")
  # 1 / √(a-d)
  INVSQRT_A_MINUS_D = BigInt.new("54469307008909316920995813868745141605393597292927456921205312896311721017578")
  # 1-d²
  ONE_MINUS_D_SQ = BigInt.new("1159843021668779879193775521855586647937357759715417654439879720876111806838")
  # (d-1)²
  D_MINUS_ONE_SQ = BigInt.new("40440834346308536858101042469323190826248399146238708352240133220865137265952")

  def concat_bytes(*arrays) : Bytes
    if arrays.size == 1
      arrays[0]
    else
      length = arrays.reduce(0) { |acc, arr| acc + arr.size }
      io = IO::Memory.new(length)
      arrays.each { |arr| io.write(arr) }
      io.to_slice
    end
  end

  # Convert between types
  # ---------------------
  def bytes_to_hex(uint8a : Bytes) : String
    hex = uint8a.hexstring
    return "0#{hex}" if hex.bytesize.odd?
    hex
  end

  def hex_to_bytes(hex : String) : Bytes
    hex = "0#{hex}" if hex.bytesize.odd?
    hex.hexbytes
  end

  def number_to_32_bytes_be(num : BigInt) : Bytes
    length = 32
    hex = num.to_s(16).rjust(length * 2, '0')
    hex_to_bytes(hex)
  end

  def number_to_32_bytes_le(num : BigInt) : Bytes
    number_to_32_bytes_be(num).reverse!
  end

  # Little-endian check for first LE bit (last BE bit)
  def ed_is_negative(num : BigInt)
    (mod(num) & One) === One
  end

  # Little Endian
  def bytes_to_number_le(uint8a : Bytes) : BigInt
    # BigInt.new("0x" + bytes_to_hex(uint8a.clone.reverse!))
    # BigInt.from_bytes(uint8a)
    BigInt.new(uint8a.clone.reverse!.hexstring, base: 16)
  end

  def bytes_255_to_number_le(bytes : Bytes) : BigInt
    Ed25519.mod(bytes_to_number_le(bytes) & (Ed25519::Two ** BigInt255 - One))
  end

  # -------------------------

  def mod(a : BigInt, b : BigInt = Curve::P) : BigInt
    res = a % b
    res >= Zero ? res : b + res
  end

  # Note: this egcd-based invert is 50% faster than powMod-based one.
  # Inverses number over modulo
  def invert(number : BigInt, modulo : BigInt = Curve::P) : BigInt
    raise ArgumentError.new("invert: expected positive integers, got n=#{number} mod=#{modulo}") if number === Zero || modulo <= Zero
    # Eucledian GCD https://brilliant.org/wiki/extended-euclidean-algorithm/
    a = mod(number, modulo)
    b = modulo
    # prettier-ignore
    x = Zero
    y = One
    u = One
    v = Zero
    while a != Zero
      q = b // a
      r = b % a
      m = x - u * q
      n = y - v * q
      # prettier-ignore
      b = a
      a = r
      x = u
      y = v
      u = m
      v = n
    end
    gcd = b
    raise Exception.new("invert: does not exist") if gcd != One
    mod(x, modulo)
  end

  # **
  # Takes a list of numbers, efficiently inverts all of them.
  # @param nums list of BigInts
  # @param p modulo
  # @returns list of inverted BigInts
  # @example
  # Ed25519.invert_batch([1n, 2n, 4n], 21n)
  # # => [1n, 11n, 16n]
  # /
  def invert_batch(nums : Array(BigInt), p : BigInt = Curve::P) : Array(BigInt)
    # puts "size = #{nums.size}"
    tmp = Array(BigInt).new(nums.size, Ed25519::Zero)
    # Walk from first to last, multiply them by each other MOD p
    last_multiplied = nums.each_with_index.reduce(One) do |acc, pair|
      num, i = pair
      next acc if num == Zero
      # puts "#{i} -> #{acc}"
      tmp[i] = acc
      Ed25519.mod(acc * num, p)
    end
    # Invert last element
    inverted = invert(last_multiplied, p)

    # Walk from last to first, multiply them by inverted each other MOD p
    (nums.size - 1).downto(0) do |i|
      num = nums[i]
      next if num.zero?
      tmp[i] = Ed25519.mod(inverted * tmp[i], p)
      inverted = Ed25519.mod(inverted * num, p)
    end

    tmp
  end

  # Does x ^ (2 ^ power) mod p. pow2(30, 4) == 30 ^ (2 ^ 4)
  def pow2(x : BigInt, power : BigInt) : BigInt
    res = x
    while power > Zero
      power -= 1
      res *= res
      res %= Curve::P
    end
    res
  end

  # Power to (p-5)/8 aka x^(2^252-3)
  # Used to calculate y - the square root of y².
  # Exponentiates it to very big number.
  # We are unwrapping the loop because it's 2x faster.
  # (2n**252n-3n).to_string(2) would produce bits [250x 1, 0, 1]
  # We are multiplying it bit-by-bit
  def pow_2_252_3(x : BigInt)
    _5n = BigInt.new(5)
    _10n = BigInt.new(10)
    _20n = BigInt.new(20)
    _40n = BigInt.new(40)
    _80n = BigInt.new(80)
    x2 = (x * x) % Curve::P
    b2 = (x2 * x) % Curve::P                      # x^3, 11
    b4 = (pow2(b2, Ed25519::Two) * b2) % Curve::P # x^15, 1111
    b5 = (pow2(b4, One) * x) % Curve::P           # x^31
    b10 = (pow2(b5, _5n) * b5) % Curve::P
    b20 = (pow2(b10, _10n) * b10) % Curve::P
    b40 = (pow2(b20, _20n) * b20) % Curve::P
    b80 = (pow2(b40, _40n) * b40) % Curve::P
    b160 = (pow2(b80, _80n) * b80) % Curve::P
    b240 = (pow2(b160, _80n) * b80) % Curve::P
    b250 = (pow2(b240, _10n) * b10) % Curve::P
    pow_p_5_8 = (pow2(b250, Ed25519::Two) * x) % Curve::P
    # ^ To pow to (p+3)/8, multiply it by x.
    {pow_p_5_8, b2}
  end

  # Ratio of u to v. Allows us to combine inversion and square root. Uses algo from RFC8032 5.1.3.
  # Constant-time
  # prettier-ignore
  def uv_ratio(u : BigInt, v : BigInt) : {is_valid: Bool, value: BigInt}
    v3 = Ed25519.mod(v * v * v)   # v³
    v7 = Ed25519.mod(v3 * v3 * v) # v⁷
    pow, _ = pow_2_252_3(u * v7)
    x = Ed25519.mod(u * v3 * pow)              # (uv³)(uv⁷)^(p-5)/8
    vx2 = Ed25519.mod(v * x * x)               # vx²
    root1 = x                                  # First root candidate
    root2 = Ed25519.mod(x * SQRT_M1)           # Second root candidate
    use_root1 = vx2 == u                       # If vx² = u (mod p), x is a square root
    use_root2 = vx2 == Ed25519.mod(-u)         # If vx² = -u, set x <-- x * 2^((p-1)/4)
    no_root = vx2 == Ed25519.mod(-u * SQRT_M1) # There is no valid root, vx² = -u√(-1)
    x = root1 if use_root1
    x = root2 if use_root2 || no_root # We return root2 anyway, for const-time
    x = Ed25519.mod(-x) if ed_is_negative(x)
    {is_valid: use_root1 || use_root2, value: x}
  end

  # Calculates 1/√(number)
  def invert_sqrt(number : BigInt)
    uv_ratio(One, number)
  end

  # Math end

  # Little-endian SHA512 with modulo n
  def sha512_modq_le(*args) : BigInt
    hash = Utils.sha512(concat_bytes(*args))
    value = bytes_to_number_le(hash)
    Ed25519.mod(value, Curve::L)
  end

  def equal_bytes(b1 : Bytes, b2 : Bytes)
    b1 == b2
  end

  def ensure_bytes(hex : Hex, expected_length : Int32? = nil) : Bytes
    # Bytes.from() instead of hash.slice() because node.js Buffer
    # is instance of Bytes, and its slice() creates **mutable** copy
    bytes = case hex
            in Bytes
              hex
            in String
              hex_to_bytes(hex)
            end
    # bytes = hex instanceof Bytes ? Bytes.from(hex) : hex_to_bytes(hex)
    raise VerifyError.new("Expected #{expected_length} bytes, got #{bytes.size}") if expected_length && bytes.size != expected_length

    bytes
  end

  # **
  # Checks for num to be in range:
  # For strict == true:  `0 <  num < max`.
  # For strict == false: `0 <= num < max`.
  # Converts non-float safe numbers to BigInts.
  # /
  def normalize_scalar(num : Int, max : BigInt, strict = true) : BigInt
    raise ArgumentError.new("Specify max value") unless max > 0
    # num = BigInt.new(num)
    case
    when strict && Zero < num && num < max
      num.to_big_i
    when !strict && Zero <= num && num < max
      num.to_big_i
    else
      raise ArgumentError.new("Expected valid scalar: 0 < scalar < max")
    end
    # if num < max
    #   if strict
    #     if (Zero < num) return num
    #   else
    #     if (Zero <= num) return num
    #   end
    # end
    # raise TypeException.new("Expected valid scalar: 0 < scalar < max")
  end

  def adjust_bytes_25519(bytes : Bytes) : Bytes
    # Section 5: For X25519, in order to decode 32 random bytes as an integer scalar,
    # set the three least significant bits of the first byte
    bytes[0] &= 248 # 0b1111_1000
    # and the most significant bit of the last to zero,
    bytes[31] &= 127 # 0b0111_1111
    # set the second most significant bit of the last byte to 1
    bytes[31] |= 64 # 0b0100_0000
    bytes
  end

  def decode_scalar_25519(n : Hex) : BigInt
    # and, finally, decode as little-endian.
    # This means that the resulting integer is of the form 2 ^ 254 plus eight times a value between 0 and 2 ^ 251 - 1(inclusive).
    bytes_to_number_le(adjust_bytes_25519(ensure_bytes(n, 32)))
  end

  # Private convenience method
  # RFC8032 5.1.5
  def get_extended_public_key(key : PrivKey)
    # Normalize BigInt / number / string to Bytes
    key_bytes = case key
                in Hex
                  ensure_bytes(key)
                in Int
                  number_to_32_bytes_be(Ed25519.normalize_scalar(key, MAX_256B))
                end
    # key =
    #   typeof key === "BigInt" || typeof key === "number"
    #     ? number_to_32_bytes_be(Ed25519.normalize_scalar(key, MAX_256B))
    #     : ensure_bytes(key)
    raise VerifyError.new("Expected 32 bytes. Key is only #{key_bytes.size} bytes") unless key_bytes.size == 32
    # hash to produce 64 bytes
    hashed = Utils.sha512(key_bytes)
    # First 32 bytes of 64b uniformingly random input are taken,
    # clears 3 bits of it to produce a random field element.
    head = adjust_bytes_25519(hashed[0, 32])
    # Second 32 bytes is called key prefix (5.1.6)
    prefix = hashed[32, 32]
    # The actual private scalar
    scalar = Ed25519.mod(bytes_to_number_le(head), Curve::L)
    # Point on Edwards curve aka public key
    point = Point::BASE.multiply(scalar)
    point_bytes = point.to_raw_bytes
    {head, prefix, scalar, point, point_bytes}
  end

  # **
  # Calculates ed25519 public key.
  # 1. private key is hashed with sha512, then first 32 bytes are taken from the hash
  # 2. 3 least significant bits of the first byte are cleared
  # RFC8032 5.1.5
  # /
  def get_public_key(private_key : PrivKey) : Bytes
    _, _, _, _, point_bytes = get_extended_public_key(private_key)
    point_bytes
  end

  # **
  # Signs message with private_key.
  # RFC8032 5.1.6
  # /
  def sign(message : Hex, private_key : Hex) : Bytes
    message = ensure_bytes(message)
    _, prefix, scalar, _, point_bytes = get_extended_public_key(private_key)
    r = sha512_modq_le(prefix, message)                       # r = hash(prefix + msg)
    r_ = Point::BASE.multiply(r)                              # R = rG
    k = sha512_modq_le(r_.to_raw_bytes, point_bytes, message) # k = hash(R + P + msg)
    s = Ed25519.mod(r + k * scalar, Curve::L)                 # s = r + kp
    Signature.new(r_, s).to_raw_bytes
  end

  # **
  # Verifies ed25519 signature against message and public key.
  # An extended group equation is checked.
  # RFC8032 5.1.7
  # Compliant with ZIP215:
  # 0 <= sig.R/public_key < 2**256 (can be >= curve.P)
  # 0 <= sig.s < l
  # Not compliant with RFC8032: it's not possible to comply to both ZIP & RFC at the same time.
  # /
  def verify(sig : SigType, message : Hex, public_key : PubKey) : Bool
    message = ensure_bytes(message)
    # When hex is passed, we check public key fully.
    # When Point instance is passed, we assume it has already been checked, for performance.
    # If user passes Point/Sig instance, we assume it has been already verified.
    # We don't check its equations for performance. We do check for valid bounds for s though
    # We always check for: a) s bounds. b) hex validity

    # if (!(public_key instanceof Point)) public_key = Point.from_hex(public_key, false)
    point = case public_key
            in Hex
              Point.from_hex(public_key, false)
            in Point
              public_key
            end

    # { r, s } = sig instanceof Signature ? sig.assert_validity() : Signature.from_hex(sig)
    signature = case sig
                in Signature
                  sig.assert_validity
                in Hex
                  Signature.from_hex(sig)
                end
    sb = ExtendedPoint::BASE.multiply_unsafe(signature.s)
    k = sha512_modq_le(signature.r.to_raw_bytes, point.to_raw_bytes, message)
    k_a = ExtendedPoint.from_affine(point).multiply_unsafe(k)
    rk_a = ExtendedPoint.from_affine(signature.r).add(k_a)
    # [8][S]B = [8]R + [8][k]A'
    rk_a.subtract(sb).multiply_unsafe(Curve::H).equals(ExtendedPoint::ZERO)
  end

  # **
  # Calculates X25519 DH shared secret from ed25519 private & public keys.
  # Curve25519 used in X25519 consumes private keys as-is, while ed25519 hashes them with sha512.
  # Which means we will need to normalize ed25519 seeds to "hashed repr".
  # @param private_key ed25519 private key
  # @param public_key ed25519 public key
  # @returns X25519 shared key
  # /
  def get_shared_secret(private_key : PrivKey, public_key : Hex) : Bytes
    head, _, _, _, _ = get_extended_public_key(private_key)
    u = Point.from_hex(public_key).to_x25519
    Curve25519.scalar_mult(head, u)
  end

  # Enable precomputes. Slows down first public_key computation by 20ms.
  Point::BASE._set_window_size(8)

  # curve25519-related code
  # Curve equation: v^2 = u^3 + A*u^2 + u
  # https://datatracker.ietf.org/doc/html/rfc7748

  # cswap from RFC7748
  def cswap(swap : BigInt, x_2 : BigInt, x_3 : BigInt) : {BigInt, BigInt}
    dummy = Ed25519.mod(swap * (x_2 - x_3))
    x_2 = Ed25519.mod(x_2 - dummy)
    x_3 = Ed25519.mod(x_3 + dummy)
    {x_2, x_3}
  end

  # x25519 from 4
  # **
  #
  # @param point_u u coordinate (x) on Montgomery Curve 25519
  # @param scalar by which the point would be multiplied
  # @returns new Point on Montgomery curve
  # /
  def montgomery_ladder(point_u : BigInt, scalar : BigInt) : BigInt
    u = Ed25519.normalize_scalar(point_u, Curve::P)
    # Section 5: Implementations MUST accept non-canonical values and process them as
    # if they had been reduced modulo the field prime.
    k = Ed25519.normalize_scalar(scalar, Curve::P)
    # The constant a24 is (486662 - 2) / 4 = 121665 for curve25519/X25519
    a24 = BigInt.new(121665)
    x_1 = u
    x_2 = One
    z_2 = Zero
    x_3 = u
    z_3 = One
    swap = Zero
    sw : {BigInt, BigInt} = {BigInt.new(0), BigInt.new(0)}
    t = BigInt.new(255 - 1)
    while t >= Zero # for (t = BigInt.new(255 - 1) t >= Zero t--) {
      k_t = (k >> t) & One
      swap ^= k_t
      sw = cswap(swap, x_2, x_3)
      x_2 = sw[0]
      x_3 = sw[1]
      sw = cswap(swap, z_2, z_3)
      z_2 = sw[0]
      z_3 = sw[1]
      swap = k_t

      a_ = x_2 + z_2
      aa_ = Ed25519.mod(a_ * a_)
      b_ = x_2 - z_2
      bb_ = Ed25519.mod(b_ * b_)
      e_ = aa_ - bb_
      c_ = x_3 + z_3
      d_ = x_3 - z_3
      da_ = Ed25519.mod(d_ * a_)
      cb_ = Ed25519.mod(c_ * b_)
      x_3 = Ed25519.mod((da_ + cb_) ** Ed25519::Two)
      z_3 = Ed25519.mod(x_1 * (da_ - cb_) ** Ed25519::Two)
      x_2 = Ed25519.mod(aa_ * bb_)
      z_2 = Ed25519.mod(e_ * (aa_ + Ed25519.mod(a24 * e_)))
      t -= 1
    end
    sw = cswap(swap, x_2, x_3)
    x_2 = sw[0]
    # x_3 = sw[1]
    sw = cswap(swap, z_2, z_3)
    z_2 = sw[0]
    # z_3 = sw[1]
    pow_p_5_8, b2 = pow_2_252_3(z_2)
    # x^(p-2) aka x^(2^255-21)
    xp2 = Ed25519.mod(pow2(pow_p_5_8, BigInt.new(3)) * b2)
    Ed25519.mod(x_2 * xp2)
  end

  def encode_u_coordinate(u : BigInt) : Bytes
    number_to_32_bytes_le(Ed25519.mod(u, Curve::P))
  end

  def decode_u_coordinate(u_enc : Hex) : BigInt
    u = ensure_bytes(u_enc, 32)
    # Section 5: When receiving such an array, implementations of X25519
    # MUST mask the most significant bit in the final byte.
    u[31] &= 127 # 0b0111_1111
    bytes_to_number_le(u)
  end
end

require "./ed25519/*"
