# frozen_string_literal: true
require 'base64url'

module WebAuthn
  class AuthenticationError < StandardError; end
  class InvalidCredentials < AuthenticationError; end

  module Utils
    def self.authenticator_decode(str)
      Base64URL.decode(str)
    end
  end
end
