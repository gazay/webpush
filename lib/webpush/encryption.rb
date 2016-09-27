require "jwt"
require "base64"

module Webpush
  module Encryption
    extend self

    def encrypt(message, p256dh, auth)
      assert_arguments(message, p256dh, auth)

      group_name = "prime256v1"
      salt = Random.new.bytes(16)

      server = OpenSSL::PKey::EC.new(group_name)
      server.generate_key
      server_public_key_bn = server.public_key.to_bn

      group = OpenSSL::PKey::EC::Group.new(group_name)
      client_public_key_bn = OpenSSL::BN.new(Base64.urlsafe_decode64(p256dh), 2)
      client_public_key = OpenSSL::PKey::EC::Point.new(group, client_public_key_bn)

      shared_secret = server.dh_compute_key(client_public_key)

      client_auth_token = Base64.urlsafe_decode64(auth)

      prk = HKDF.new(shared_secret, salt: client_auth_token, algorithm: 'SHA256', info: "Content-Encoding: auth\0").next_bytes(32)

      context = create_context(client_public_key_bn, server_public_key_bn)

      content_encryption_key_info = create_info('aesgcm', context)
      content_encryption_key = HKDF.new(prk, salt: salt, info: content_encryption_key_info).next_bytes(16)

      nonce_info = create_info('nonce', context)
      nonce = HKDF.new(prk, salt: salt, info: nonce_info).next_bytes(12)

      ciphertext = encrypt_payload(message, content_encryption_key, nonce)

      {
        ciphertext: ciphertext,
        salt: salt,
        server_public_key_bn: convert16bit(server_public_key_bn),
        shared_secret: shared_secret
      }
    end

    def generate_vapid_keys
      group_name = "prime256v1"

      ecdsa_key = OpenSSL::PKey::EC.new group_name
      ecdsa_key.generate_key

      {
        public_key: ecdsa_key.public_key.to_bn.to_s(2),
        private_key: ecdsa_key.private_key.to_s(2),
        key: ecdsa_key
      }
    end

    # audience - url of host site, format: URL
    # subject - mailto email address, format: URL or email address
    # public_key - VAPID public key, 65 byte array
    # private_key - VAPID private key, 32 byte array
    # ttl - number of seconds
    def vapid_headers(audience:, subject:, public_key:, private_key:, expiration: (Time.now.to_i + (12 * 60 * 60)))
      group_name = "prime256v1"

      header = {
        "typ" => 'JWT',
        "alg" => 'ES256'
      }

      jwt_payload = {
        "aud" => audience,
        "exp" => expiration,
        "sub" => subject
      }

      puts "header #{header.inspect}"
      puts "jwt_payload #{jwt_payload.inspect}"

      public_key = Base64.urlsafe_decode64(public_key)
      private_key = Base64.urlsafe_decode64(private_key)

      public_key_bn = OpenSSL::BN.new(public_key, 2)
      private_key_bn = OpenSSL::BN.new(private_key, 2)

      ecdsa_key = OpenSSL::PKey::EC.new group_name
      ecdsa_key.public_key = OpenSSL::PKey::EC::Point.new(OpenSSL::PKey::EC::Group.new(group_name), public_key_bn)
      ecdsa_key.private_key = private_key_bn

      jwt = JWT.encode jwt_payload, ecdsa_key, 'ES256', header

      p256ecdsa = Base64.urlsafe_encode64(public_key).delete("=")

      {
        "Authorization" => "WebPush #{jwt}",
        "Crypto-Key" => "p256ecdsa=#{p256ecdsa}"
      }
    end

    private

    def create_context(client_public_key, server_public_key)
      c = convert16bit(client_public_key)
      s = convert16bit(server_public_key)
      context = "\0"
      context += [c.bytesize].pack("n*")
      context += c
      context += [s.bytesize].pack("n*")
      context += s
      context
    end

    def encrypt_payload(plaintext, content_encryption_key, nonce)
      cipher = OpenSSL::Cipher.new('aes-128-gcm')
      cipher.encrypt
      cipher.key = content_encryption_key
      cipher.iv = nonce
      padding = cipher.update("\0\0")
      text = cipher.update(plaintext)

      e_text = padding + text + cipher.final
      e_tag = cipher.auth_tag

      e_text + e_tag
    end

    def create_info(type, context)
      info = "Content-Encoding: "
      info += type
      info += "\0"
      info += "P-256"
      info += context
      info
    end

    def convert16bit(key)
      [key.to_s(16)].pack("H*")
    end

    def convert_U8int_Array(key)
      [key.to_s(16)].pack("H*").unpack('C*')
    end

    def assert_arguments(message, p256dh, auth)
      raise ArgumentError, "message cannot be blank" if blank?(message)
      raise ArgumentError, "p256dh cannot be blank" if blank?(p256dh)
      raise ArgumentError, "auth cannot be blank" if blank?(auth)
    end

    def blank?(value)
      value.nil? || value.empty?
    end
  end
end
