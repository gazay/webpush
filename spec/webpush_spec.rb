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

  describe "#encrypt" do
    let(:p256dh) do
      group = "prime256v1"
      curve = OpenSSL::PKey::EC.new(group)
      curve.generate_key
      encode(curve.public_key.to_bn.to_s(2))
    end

    let(:auth) { encode(Random.new.bytes(16)) }

    it "returns ECDH encrypted cipher text, salt, and server_public_key" do
      payload = Webpush.send(:encrypt, "Hello World", p256dh, auth)

      encrypted = payload.fetch(:ciphertext)

      decrypted_data = ECE.decrypt(encrypted,
        key: payload.fetch(:shared_secret),
        salt: payload.fetch(:salt),
        server_public_key: payload.fetch(:server_public_key_bn),
        user_public_key: decode(p256dh),
        auth: decode(auth))

      expect(decrypted_data).to eq("Hello World")
    end

    def encode(bytes)
      Base64.urlsafe_encode64(bytes)
    end

    def decode(bytes)
      Base64.urlsafe_decode64(bytes)
    end
  end
end
