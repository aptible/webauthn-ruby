# frozen_string_literal: true

module WebAuthn
  class AuthenticatorResponse
    def initialize(client_data_json:)
      @client_data_json = client_data_json
    end

    def valid!(original_challenge, original_origin, rp_id: nil)
      raise WebAuthn::InvalidCredentials, 'Invalid type' unless valid_type

      raise WebAuthn::InvalidCredentials, 'Invalid challenge' unless valid_challenge?(original_challenge)

      raise WebAuthn::InvalidCredentials, 'Invalid origin' unless valid_origin?(original_origin)

      valid_rp = valid_rp_id?(rp_id || rp_id_from_origin(original_origin))
      raise WebAuthn::InvalidCredentials, 'Invalid rp_id' unless valid_rp

      raise WebAuthn::InvalidCredentials, 'Invalid authenticator data' unless authenticator_data.valid?

      raise WebAuthn::InvalidCredentials, 'User flagged' unless authenticator_data.user_flagged?

      true
    end

    def client_data
      @client_data ||= WebAuthn::ClientData.new(client_data_json)
    end

    def valid_type?
      client_data.type == type
    end

    def valid_challenge?(original_challenge)
      WebAuthn::Utils.authenticator_decode(client_data.challenge) == original_challenge
    end

    def valid_origin?(original_origin)
      client_data.origin == original_origin
    end

    def valid_rp_id?(rp_id)
      OpenSSL::Digest::SHA256.digest(rp_id) == authenticator_data.rp_id_hash
    end

    private

    attr_reader :client_data_json

    def rp_id_from_origin(original_origin)
      URI.parse(original_origin).host
    end

    def type
      raise NotImplementedError, "Please define #type method in subclass"
    end
  end
end
