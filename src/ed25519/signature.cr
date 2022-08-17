# **
# EDDSA signature.
# /
class Ed25519::Signature
  property r : Point
  property s : BigInt

  def initialize(@r : Point, @s : BigInt)
    self.assertValidity
  end

  def self.fromHex(hex : Hex) : Signature
    bytes = Ed25519.ensureBytes(hex, 64)
    r = Point.fromHex(bytes[0, 32], false)
    s = Ed25519.bytesToNumberLE(bytes[32, 32])
    Signature.new(r, s)
  end

  def assertValidity
    # 0 <= s < l
    Ed25519.normalizeScalar(@s, Curve::L, false)
    self
  end

  def toRawBytes
    u8 = Bytes.new(64)
    @r.toRawBytes.copy_to(u8)
    Ed25519.numberTo32BytesLE(self.s).each_with_index { |elem, i| u8[32 + i] = elem }
    u8
  end

  def toHex
    bytesToHex(self.toRawBytes)
  end
end
