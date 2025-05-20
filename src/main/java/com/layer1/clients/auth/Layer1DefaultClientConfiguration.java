package com.layer1.clients.auth;

import lombok.Builder;
import lombok.Value;

@Value
@Builder
public class Layer1DefaultClientConfiguration implements Layer1ClientConfiguration {
  String tokenUrl;
  String basePath;
  String clientId;
  String clientSecret;
  String signingPrivateKey;
}
