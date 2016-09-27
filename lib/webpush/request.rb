module Webpush

  class ResponseError < RuntimeError
  end

  class InvalidSubscription < ResponseError
  end

  class Request
    def initialize(endpoint, options = {})
      @endpoint = endpoint
      @options = default_options.merge(options)
      @payload = @options.delete(:payload) || {}
      @vapid   = @options.delete(:vapid) || {}
    end

    def perform
      uri = URI.parse(@endpoint)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = true
      req = Net::HTTP::Post.new(uri.request_uri, headers)
      req.body = body
      resp = http.request(req)

      # if resp.is_a?(Net::HTTPGone) ||   #Firefox unsubscribed response
      #     (resp.is_a?(Net::HTTPBadRequest) && resp.message == "UnauthorizedRegistration")  #Chrome unsubscribed response
      #   raise InvalidSubscription.new(resp.inspect)
      # elsif !resp.is_a?(Net::HTTPSuccess)  #unknown/unhandled response error
      #   raise ResponseError.new "host: #{uri.host}, #{resp.inspect}\nbody:\n#{resp.body}"
      # end

      resp
    end

    def headers
      headers = {}
      headers["Content-Type"] = "application/octet-stream"
      headers["Ttl"]          = ttl

      if encrypted_payload?
        headers["Content-Encoding"] = "aesgcm"
        headers["Encryption"] = "salt=#{salt_param}"
        headers["Crypto-Key"] = "p256dh=#{dh_param}"
      end

      # headers["Authorization"] = "key=#{api_key}" if api_key?
      headers["Content-Length"] = body.length.to_s

      if @vapid.any?
        vapid = Webpush::Encryption.vapid_headers(@vapid)

        headers['Authorization'] = vapid['Authorization']
        headers['Crypto-Key'] = [headers['Crypto-Key'], vapid['Crypto-Key']].compact.join(";")
        Rails.logger.info("Crypto-Key.................")
        Rails.logger.info(headers["Crypto-Key"])
      end

      Rails.logger.info("Headers")
      Rails.logger.info(headers.inspect)

      headers
    end

    def body
      @payload.fetch(:ciphertext, "")
    end

    private

    def ttl
      @options.fetch(:ttl).to_s
    end

    def api_key
      @options.fetch(:api_key, nil)
    end

    def api_key?
      return false
      # !(api_key.nil? || api_key.empty?) && @endpoint =~ /\Ahttps:\/\/(android|gcm-http)\.googleapis\.com/
    end

    def encrypted_payload?
      [:ciphertext, :server_public_key_bn, :salt].all? { |key| @payload.has_key?(key) }
    end

    def dh_param
      Base64.urlsafe_encode64(@payload.fetch(:server_public_key_bn)).delete('=')
    end

    def salt_param
      Base64.urlsafe_encode64(@payload.fetch(:salt)).delete('=')
    end

    def default_options
      {
        api_key: nil,
        ttl: 60*60*24*7*4 # 4 weeks
      }
    end
  end
end
