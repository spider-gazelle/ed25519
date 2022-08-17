require "./spec_helper"

describe Ed25519::SigningKey do
  signing_key = Ed25519::SigningKey.new
  verify_key = signing_key.verify_key
  message = "example message"
  signature = signing_key.sign(message)

  it "verifies messages with good signatures" do
    verify_key.verify(signature, message).should be_true
  end

  it "raises Ed25519::VerifyError on bad signatures" do
    io = IO::Memory.new
    io.write signature
    io.write_byte 0x45_u8
    bad_signature = io.to_slice

    # TODO:: fix this to be a scoped error
    expect_raises(Exception) { verify_key.verify(bad_signature, message) }
    verify_key.verify(signature, "wrong message").should be_false
  end
end
