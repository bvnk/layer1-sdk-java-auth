package com.layer1.clients.auth;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class Layer1DigestTest {
  private String base64PrivateKey;
  private String clientId = "test-client";
  private Layer1Digest digest;

  @BeforeEach
  void setUp() throws Exception {
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    KeyPair pair = keyGen.generateKeyPair();
    PrivateKey privateKey = pair.getPrivate();
    base64PrivateKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());
    digest = new Layer1Digest(base64PrivateKey, clientId);
  }

  @Test
  void testBuildHeaders_withPayload() {
    String url = "https://api.example.com/resource";
    String payload = "{\"foo\":\"bar\"}";
    String method = "POST";
    Map<String, String> headers = digest.buildHeaders(url, payload, method);
    assertTrue(headers.containsKey("Content-Digest"));
    assertTrue(headers.containsKey("Signature-Input"));
    assertTrue(headers.containsKey("Signature"));
    assertTrue(headers.get("Signature-Input").startsWith("sig="));
    assertTrue(headers.get("Signature").startsWith("sig=:"));
  }

  @Test
  void testBuildHeaders_withoutPayload() {
    String url = "https://api.example.com/resource";
    String method = "GET";
    Map<String, String> headers = digest.buildHeaders(url, null, method);
    assertFalse(headers.containsKey("Content-Digest"));
    assertTrue(headers.containsKey("Signature-Input"));
    assertTrue(headers.containsKey("Signature"));
  }

  @Test
  void testPrepareKey_removesHeadersAndWhitespace() throws Exception {
    String rawKey =
        "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC...\n-----END PRIVATE KEY-----";
    Method prepareKey = Layer1Digest.class.getDeclaredMethod("prepareKey", String.class);
    prepareKey.setAccessible(true);
    String result = (String) prepareKey.invoke(digest, rawKey);
    assertFalse(result.contains("BEGIN PRIVATE KEY"));
    assertFalse(result.contains("END PRIVATE KEY"));
    assertFalse(result.contains("\n"));
    assertFalse(result.contains(" "));
  }

  @Test
  void testCreateDigest_andGetDigest() throws Exception {
    Method createDigest =
        Layer1Digest.class.getDeclaredMethod("createDigest", String.class, String.class);
    createDigest.setAccessible(true);
    String digestStr = (String) createDigest.invoke(digest, "sha-256", "test-data");
    assertTrue(digestStr.startsWith("sha-256=:"));
  }

  @Test
  void testSignatureVerification() throws Exception {
    // Load private key from PEM
    String privateKeyPem =
        new String(Files.readAllBytes(Paths.get("src/test/resources/layer1-test-private-key.pem")));
    String privateKeyBase64 =
        privateKeyPem
            .replaceAll("-----BEGIN PRIVATE KEY-----", "")
            .replaceAll("-----END PRIVATE KEY-----", "")
            .replaceAll("[\r\n]+", "")
            .replaceAll("\\s+", "");
    byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64);
    PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
    PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec);
    String clientId = "test-client";
    Layer1Digest digest =
        new Layer1Digest(Base64.getEncoder().encodeToString(privateKey.getEncoded()), clientId);

    // Load public key from PEM
    String publicKeyPem =
        new String(Files.readAllBytes(Paths.get("src/test/resources/layer1-test-public-key.pem")));
    String publicKeyBase64 =
        publicKeyPem
            .replaceAll("-----BEGIN PUBLIC KEY-----", "")
            .replaceAll("-----END PUBLIC KEY-----", "")
            .replaceAll("[\r\n]+", "")
            .replaceAll("\\s+", "");
    byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
    X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
    PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);

    String url = "https://api.example.com/resource";
    String payload = "{\"foo\":\"bar\"}";
    String method = "POST";
    Map<String, String> headers = digest.buildHeaders(url, payload, method);

    // Extract signature and signature params
    String signatureHeader = headers.get("Signature");
    assertNotNull(signatureHeader);
    String signatureB64 = signatureHeader.replaceFirst("sig=:(.*):", "$1");
    byte[] signature = Base64.getDecoder().decode(signatureB64);

    String signatureInput = headers.get("Signature-Input");
    assertNotNull(signatureInput);
    String signatureParams = signatureInput.replaceFirst("sig=", "");

    String contentDigest = headers.get("Content-Digest");
    String contentDigestLine =
        contentDigest == null ? "" : "\"content-digest\": " + contentDigest + "\n";

    String signatureBase =
        String.format(
            "\"@method\": %s\n\"@target-uri\": %s\n%s\"@signature-params\": %s",
            method.toUpperCase(), url, contentDigestLine, signatureParams);

    // Verify signature
    java.security.Signature verifier = java.security.Signature.getInstance("SHA256withRSA");
    verifier.initVerify(publicKey);
    verifier.update(signatureBase.getBytes());
    assertTrue(verifier.verify(signature), "Signature should be valid for the payload and headers");
  }
}
