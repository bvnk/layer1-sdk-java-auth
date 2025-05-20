package com.layer1.clients.auth;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class Layer1Digest {
  private static final String SIGNATURE_ALGORITHM = "rsa-v1_5-sha256";
  private static final String DIGEST_ALGORITHM = "sha-256";

  private final PrivateKey signingKey;

  private final String clientId;

  /**
   * @param signingPrivateKey Base64 encoded private key
   * @param clientId OAuth2 Client ID
   */
  public Layer1Digest(String signingPrivateKey, String clientId) {
    this.clientId = clientId;

    try {
      String preparedKey = prepareKey(signingPrivateKey);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      signingKey =
          keyFactory.generatePrivate(
              new PKCS8EncodedKeySpec(Base64.getDecoder().decode(preparedKey)));
    } catch (Exception e) {
      throw new RuntimeException("Failed to load private key", e);
    }
  }

  /**
   * This methods build the necessary signature headers and returns them as a map
   *
   * @param url The full URL of the request
   * @param payload The body of the request (if any, POST, etc)
   * @param method The HTTP method of the request
   * @return A map of headers
   */
  public Map<String, String> buildHeaders(String url, String payload, String method) {
    Map<String, String> headerParams = new HashMap<>();

    String contentDigest = null;

    if (!Objects.isNull(payload) && !payload.isEmpty()) {
      try {
        contentDigest = createDigest(DIGEST_ALGORITHM, payload);
        headerParams.put("Content-Digest", contentDigest);
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException("Failed to create digest", e);
      }
    }

    String signatureParameters = createSignatureParameters(contentDigest);
    headerParams.put("Signature-Input", "sig=" + signatureParameters);

    try {
      headerParams.put(
          "Signature",
          String.format(
              "sig=:%s:",
              sign(
                  String.format(
                      "\"@method\": %s%n\"@target-uri\": %s%n%s\"@signature-params\": %s",
                      method.toUpperCase(),
                      url,
                      contentDigest == null ? "" : "\"content-digest\": " + contentDigest + "\n",
                      signatureParameters),
                  signingKey)));
    } catch (Exception e) {
      throw new RuntimeException("Failed to sign request", e);
    }

    return headerParams;
  }

  /**
   * Sign the request using SHA256withRSA
   *
   * @param signatureBase
   * @param privateKey
   * @return
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeyException
   * @throws SignatureException
   */
  private String sign(String signatureBase, PrivateKey privateKey)
      throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    Signature signer = Signature.getInstance("SHA256withRSA");
    signer.initSign(privateKey);
    signer.update(signatureBase.getBytes());
    return Base64.getEncoder().encodeToString(signer.sign());
  }

  /**
   * Assemble the RFC 9421 signature parameters
   *
   * @param contentDigest
   * @return
   */
  private String createSignatureParameters(String contentDigest) {
    return String.format(
        "(\"@method\" \"@target-uri\"%s);created=%d;keyid=\"%s\";alg=\"%s\"",
        contentDigest == null ? "" : " \"content-digest\"",
        Instant.now().toEpochMilli() / 1000,
        clientId,
        SIGNATURE_ALGORITHM);
  }

  /**
   * Create and prepare the digest for the request for the content-digest header
   *
   * @param digestAlgorithm
   * @param data
   * @return
   * @throws NoSuchAlgorithmException
   */
  private String createDigest(String digestAlgorithm, String data) throws NoSuchAlgorithmException {
    return String.format("%s=:%s:", digestAlgorithm, getDigest(digestAlgorithm, data));
  }

  private String getDigest(String algorithm, String data) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance(algorithm);
    byte[] hash = digest.digest(data.getBytes());
    return Base64.getEncoder().encodeToString(hash);
  }

  /**
   * Remove the header and footer from the private key if generated via openssl etc
   *
   * @param rawKey
   * @return
   */
  private String prepareKey(String rawKey) {
    String newKey = rawKey.replace("-----BEGIN PRIVATE KEY-----", "");
    newKey = newKey.replace("-----END PRIVATE KEY-----", "");
    return newKey.replaceAll("\\s+", "");
  }
}
