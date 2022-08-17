# ed25519 is Twisted Edwards curve with equation of
# ```
# −x² + y² = 1 − (121665/121666) * x² * y²
# ```
module Ed25519::Curve
  # Param: a
  A = BigInt.new(-1)
  # Equal to -121665/121666 over finite field.
  # Negative number is P - number, and division is invert(number, P)
  D = BigInt.new("37095705934669439343138083508754565189542113879843219016388785533085940283555")
  # Finite field 𝔽p over which we'll do calculations
  P = Ed25519::Two ** BigInt255 - BigInt.new(19)
  # Subgroup order: how many points ed25519 has
  L = CURVE_ORDER # in rfc8032 it's called l
  N = CURVE_ORDER # backwards compatibility
  # Cofactor
  H = BigInt.new(8)
  # Base point (x, y) aka generator point
  Gx = BigInt.new("15112221349535400772501151409588531511454012693041857206046113283949847762202")
  Gy = BigInt.new("46316835694926478169428394003475163141307993866256225615783033603165251855960")
end
