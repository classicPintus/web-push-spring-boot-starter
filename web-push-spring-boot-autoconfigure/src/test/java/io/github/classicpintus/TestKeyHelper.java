package io.github.classicpintus;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;

final class TestKeyHelper {

    private static final SecureRandom RNG = new SecureRandom();
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    private TestKeyHelper() {}

    static KeyPair generateP256KeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    static String encodePrivateKey(ECPrivateKey key) {
        return B64.encodeToString(toFixed32(key.getS().toByteArray()));
    }

    static String encodePublicKey(ECPublicKey key) {
        return B64.encodeToString(uncompressedPoint(key));
    }

    static String base64Url(byte[] data) {
        return B64.encodeToString(data);
    }

    static byte[] uncompressedPoint(ECPublicKey key) {
        byte[] x = toFixed32(key.getW().getAffineX().toByteArray());
        byte[] y = toFixed32(key.getW().getAffineY().toByteArray());
        byte[] result = new byte[65];
        result[0] = 0x04;
        System.arraycopy(x, 0, result, 1, 32);
        System.arraycopy(y, 0, result, 33, 32);
        return result;
    }

    static byte[] toFixed32(byte[] bytes) {
        if (bytes.length == 32) return bytes;
        if (bytes.length == 33 && bytes[0] == 0) return Arrays.copyOfRange(bytes, 1, 33);
        byte[] result = new byte[32];
        System.arraycopy(bytes, 0, result, 32 - bytes.length, bytes.length);
        return result;
    }

    static PushSubscription randomSubscription(String endpoint) throws Exception {
        KeyPair kp = generateP256KeyPair();
        byte[] authSecret = new byte[16];
        RNG.nextBytes(authSecret);
        return new PushSubscription(
                endpoint,
                encodePublicKey((ECPublicKey) kp.getPublic()),
                base64Url(authSecret));
    }

    static String[] randomSubscriptionKeys() throws Exception {
        KeyPair kp = generateP256KeyPair();
        byte[] authSecret = new byte[16];
        RNG.nextBytes(authSecret);
        return new String[]{
                encodePublicKey((ECPublicKey) kp.getPublic()),
                base64Url(authSecret)
        };
    }

    static String[] decodeJwtParts(String authorizationHeader) {
        String prefix = "vapid t=";
        int comma = authorizationHeader.indexOf(",k=");
        String jwt = authorizationHeader.substring(prefix.length(), comma);
        return jwt.split("\\.");
    }

    static String decodeJwtPayload(String authorizationHeader) {
        String[] parts = decodeJwtParts(authorizationHeader);
        return new String(Base64.getUrlDecoder().decode(parts[1]), java.nio.charset.StandardCharsets.UTF_8);
    }
}
