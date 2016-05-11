require 'spec_helper'

describe Webpush::Encryption do
  describe "#encrypt" do
    let(:p256dh) do
      group = "prime256v1"
      curve = OpenSSL::PKey::EC.new(group)
      curve.generate_key
      encode64(curve.public_key.to_bn.to_s(2))
    end

    let(:auth) { encode64(Random.new.bytes(16)) }

    it "returns ECDH encrypted cipher text, salt, and server_public_key" do
      payload = Webpush::Encryption.encrypt("Hello World", unescape_base64(p256dh), unescape_base64(auth))

      encrypted = payload.fetch(:ciphertext)

      decrypted_data = ECE.decrypt(encrypted,
        key: payload.fetch(:shared_secret),
        salt: payload.fetch(:salt),
        server_public_key: payload.fetch(:server_public_key_bn),
        user_public_key: decode64(p256dh),
        auth: decode64(auth))

      expect(decrypted_data).to eq("Hello World")
    end

    def encode64(bytes)
      Base64.urlsafe_encode64(bytes)
    end

    def decode64(bytes)
      Base64.urlsafe_decode64(bytes)
    end

    def unescape_base64(base64)
      base64.gsub(/_|\-/, "_" => "/", "-" => "+")
    end
  end
end
