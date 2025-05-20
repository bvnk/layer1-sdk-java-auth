package com.layer1.clients.auth;

public interface Layer1ClientConfiguration {
  String getTokenUrl();

  String getBasePath();

  String getClientId();

  String getClientSecret();

  /**
   * Gets the private key for the client for signed endpoints.
   *
   * <p>Private key should be in Base64 encoded PEM format.
   *
   * @return Base64 encoded PEM format private key
   */
  String getSigningPrivateKey();
}
