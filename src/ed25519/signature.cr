# **
# EDDSA signature.
# /
class Ed25519::Signature
  property r : Point
  property s : BigInt

  def initialize(@r : Point, @s : BigInt)
    self.assert_validity
  end

  def self.from_hex(hex : Hex) : Signature
    bytes = Ed25519.ensure_bytes(hex, 64)
    r = Point.from_hex(bytes[0, 32], false)
    s = Ed25519.bytes_to_number_le(bytes[32, 32])
    Signature.new(r, s)
  end

  def assert_validity
    # 0 <= s < l
    Ed25519.normalize_scalar(@s, Curve::L, false)
    self
  end

  def to_raw_bytes
    u8 = Bytes.new(64)
    @r.to_raw_bytes.copy_to(u8)
    Ed25519.number_to_32_bytes_le(self.s).each_with_index { |elem, i| u8[32 + i] = elem }
    u8
  end

  def to_hex
    bytes_to_hex(self.to_raw_bytes)
  end
end
