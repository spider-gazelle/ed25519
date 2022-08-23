# ed25519 [![CI](https://github.com/spider-gazelle/ed25519/actions/workflows/ci.yml/badge.svg)](https://github.com/spider-gazelle/ed25519/actions/workflows/ci.yml)

A crystal lang implementation of the Ed25519 elliptic curve public-key signature system
described in [RFC 8032].

[RFC 8032]: https://tools.ietf.org/html/rfc8032

## What is Ed25519?

Ed25519 is a modern implementation of a [Schnorr signature] system using
elliptic curve groups.

Ed25519 provides a 128-bit security level, that is to say, all known attacks
take at least 2^128 operations, providing the same security level as AES-128,
NIST P-256, and RSA-3072.

![Ed25519 Diagram](https://raw.githubusercontent.com/RubyCrypto/ed25519/master/ed25519.png)

Ed25519 has a number of unique properties that make it one of the best-in-class
digital signature algorithms:

* ***Small keys***: Ed25519 keys are only 256-bits (32 bytes), making them
  small enough to easily copy around. Ed25519 also allows the public key
  to be derived from the private key, meaning that it doesn't need to be
  included in a serialized private key in cases you want both.
* ***Small signatures***: Ed25519 signatures are only 512-bits (64 bytes),
  one of the smallest signature sizes available.
* ***Deterministic***: Unlike (EC)DSA, Ed25519 does not rely on an entropy
  source when signing messages. This can be a potential attack vector if
  the entropy source is not generating good random numbers. Ed25519 avoids
  this problem entirely and will always generate the same signature for the
  same data.
* ***Collision Resistant***: Hash-function collisions do not break this
  system. This adds a layer of defense against the possibility of weakness
  in the selected hash function.

You can read more on [Dan Bernstein's Ed25519 site](http://ed25519.cr.yp.to/).

[Schnorr signature]: https://en.wikipedia.org/wiki/Schnorr_signature

## Usage

```crystal

require "ed25519"

# Generate a new random signing key
signing_key = Ed25519::SigningKey.new

# Sign a message with the signing key
message = "example message"
signature = signing_key.sign(message)

# Obtain the verify key for a given signing key
verify_key = signing_key.verify_key

# Check the validity of a signature
verify_key.verify(signature, message)

```

### Serializing Keys

Keys can be serialized as 32-byte binary strings as follows:

```crystal

signature_key_bytes = signing_key.key_bytes.hexstring
verify_key_bytes = verify_key.key_bytes.hexstring

```

The binary serialization can be passed directly into the constructor for a given key type

```crystal

signing_key = Ed25519::SigningKey.new(signature_key_bytes.hexbytes)
verify_key  = Ed25519::VerifyKey.new(verify_key_bytes.hexbytes)

```

## Credit

The original crystal port was done by [davidkellis](https://github.com/davidkellis/noble-ed25519-cr)
based on the javascript implementation by [paulmillr](https://github.com/paulmillr/noble-ed25519)
Interface copied from the Ruby implementation by [tarcieri](https://github.com/RubyCrypto/ed25519)
