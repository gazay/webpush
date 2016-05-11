require 'spec_helper'

describe Webpush do
  let(:message) { JSON.generate({ body: 'body' }) }
  let(:p256dh) { 'BJSoGlbnOdsRScNlGmzKirnX9gF7XG1rGgIwP_BkxUcnQ7U_ezqSxyyu_Ghs17nom_orwTYctWfj2ZJsbqNj748' }
  let(:auth) { '2H6Lqvlpul3hdBqDNbCytw' }

  let(:expected_body) { "m\x04\xF9X)\x10\xCC\xBF\xD5\x9B\xB7\xC5Yc`\xDA\xFCE\x13#i*a\xE8\xB2\xA2\xC5\xA2\x00Y\xB0\xAFT" }
  let(:expected_headers) do
    {
      'Accept'=>'*/*',
      'Accept-Encoding'=>'gzip;q=1.0,deflate;q=0.6,identity;q=0.3',
      'Content-Encoding'=>'aesgcm',
      'Content-Type'=>'application/octet-stream',
      'Crypto-Key'=>'dh=BDclQQTQwPjSTRiz_9sY-U1LqALL59IDfQmQfcUNzJHQLrQQGaLwxtv5YceTFrPz66C6SSrV-5wWv8oMX4BoSPw',
      'Encryption'=>'salt=Dh0yTB2w1MRAwywNk4DYbg',
      'Ttl'=>'2419200',
      'User-Agent'=>'Ruby'
    }
  end

  it 'has a version number' do
    expect(Webpush::VERSION).not_to be nil
  end

  shared_examples 'request headers' do
    it 'calls the relevant service with the correct headers' do
      stub_request(:post, expected_endpoint).
        with(body: expected_body, headers: expected_headers).
        to_return(:status => 200, :body => "", :headers => {})

      Webpush.payload_send(message: message, endpoint: endpoint, p256dh: p256dh, auth: auth)
    end
  end

  context 'chrome endpoint' do
    let(:endpoint) { 'https://android.googleapis.com/gcm/send/subscription-id' }
    let(:expected_endpoint) { 'https://gcm-http.googleapis.com/gcm/subscription-id' }

    include_examples 'request headers'
  end

  context 'firefox endpoint' do
    let(:endpoint) { 'https://updates.push.services.mozilla.com/push/v1/subscription-id' }
    let(:expected_endpoint) { endpoint }

    include_examples 'request headers'
  end

  def unescape_base64(base64)
    base64.gsub(/_|\-/, "_" => "/", "-" => "+")
  end

  describe "#encrypt" do
    it "returns ECDH encrypted cipher text, salt, and server_public_key" do
      message = "Hello World"
      payload = Webpush.send(:encrypt, message, unescape_base64(p256dh), unescape_base64(auth))
      encrypted = payload.fetch(:ciphertext)
      salt = payload.fetch(:salt)
      server_public_key = payload.fetch(:server_public_key_bn)
      shared_secret = payload.fetch(:shared_secret)

      decrypted_data = ECE.decrypt(encrypted,
        key: shared_secret,
        salt: salt,
        server_public_key: server_public_key,
        user_public_key: Base64.urlsafe_decode64(p256dh),
        auth: Base64.urlsafe_decode64(auth))

      expect(decrypted_data).to eq("Hello World")
    end
  end

  describe "#encrypt_2" do
    it "returns ECDH encrypted cipher text, salt, and server_public_key" do
      # p256dh = Base64.urlsafe_encode64(Random.new.bytes(65))
      # auth = Base64.urlsafe_encode64(Random.new.bytes(16))
      message = "Hello World"
      payload = Webpush.send(:encrypt_2, message, p256dh, auth)
      encrypted = payload.fetch(:ciphertext)
      salt = payload.fetch(:salt)
      server_public_key = payload.fetch(:server_public_key_bn)
      shared_secret = payload.fetch(:shared_secret)

      decrypted_data = ECE.decrypt(encrypted,
        key: shared_secret,
        salt: salt,
        server_public_key: server_public_key,
        user_public_key: Base64.urlsafe_decode64(p256dh),
        auth: Base64.urlsafe_decode64(auth))

      expect(decrypted_data).to eq("Hello World")
    end
  end
end
