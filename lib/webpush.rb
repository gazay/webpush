require 'openssl'
require 'base64'
require 'hkdf'
require 'net/http'
require 'json'

require 'webpush/version'
require 'webpush/encryption'
require 'webpush/request'

module Webpush

  # It is temporary URL until supported by the GCM server.
  GCM_URL = 'https://android.googleapis.com/gcm/send'
  TEMP_GCM_URL = 'https://gcm-http.googleapis.com/gcm'

  class << self
    def payload_send(message:, endpoint:, p256dh:, auth:, **options)
      endpoint = endpoint.gsub(GCM_URL, TEMP_GCM_URL)

      payload = Webpush::Encryption.encrypt(message, p256dh, auth)
      # push_server_post(endpoint, payload, api_key)

      Webpush::Request.new(endpoint, payload, options).perform
    end

    private

    def push_server_post(endpoint, payload, api_key = "")
      uri = URI.parse(endpoint)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
      header = {
          "Content-Type" => "application/octet-stream",
          "Content-Encoding" => "aesgcm",
          "Encryption" => "salt=#{Base64.urlsafe_encode64(payload[:salt]).delete('=')}",
          "Crypto-Key" => "dh=#{Base64.urlsafe_encode64(payload[:server_public_key_bn]).delete('=')}",
          "Ttl"        => "2419200"
      }
      header["Authorization"] = "key=#{api_key}" unless api_key.nil? || api_key.empty?
      req = Net::HTTP::Post.new(uri.request_uri, header)
      req.body = payload[:ciphertext]
      res = http.request(req)
      res.code == "201"
    rescue
      false
    end
  end
end
