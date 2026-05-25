package io.github.classicpintus.crypto;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

final class EcUtils {

    static final String CURVE = "secp256r1";
    static final String EC = "EC";
    static final int UNCOMPRESSED_POINT_LENGTH = 65;
    static final int COORDINATE_LENGTH = 32;
    static final byte UNCOMPRESSED_MARKER = 0x04;

    private static final ECParameterSpec P256_SPEC = loadP256Spec();
    private static final KeyFactory EC_KEY_FACTORY = loadEcKeyFactory();

    private EcUtils() {}

    static ECParameterSpec p256Spec() {
        return P256_SPEC;
    }

    static KeyFactory ecKeyFactory() {
        return EC_KEY_FACTORY;
    }

    static byte[] uncompressedPoint(ECPublicKey key) {
        byte[] x = toFixed32(key.getW().getAffineX().toByteArray());
        byte[] y = toFixed32(key.getW().getAffineY().toByteArray());
        byte[] result = new byte[UNCOMPRESSED_POINT_LENGTH];
        result[0] = UNCOMPRESSED_MARKER;
        System.arraycopy(x, 0, result, 1, COORDINATE_LENGTH);
        System.arraycopy(y, 0, result, 1 + COORDINATE_LENGTH, COORDINATE_LENGTH);
        return result;
    }

    static byte[] toFixed32(byte[] bytes) {
        if (bytes.length == COORDINATE_LENGTH) return bytes;
        if (bytes.length == COORDINATE_LENGTH + 1 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, COORDINATE_LENGTH + 1);
        }
        if (bytes.length > COORDINATE_LENGTH) {
            throw new IllegalArgumentException("EC coordinate exceeds 32 bytes: " + bytes.length);
        }
        byte[] result = new byte[COORDINATE_LENGTH];
        System.arraycopy(bytes, 0, result, COORDINATE_LENGTH - bytes.length, bytes.length);
        return result;
    }

    static ECPublicKey decodeUncompressedPoint(byte[] bytes) throws GeneralSecurityException {
        if (bytes.length != UNCOMPRESSED_POINT_LENGTH || bytes[0] != UNCOMPRESSED_MARKER) {
            throw new IllegalArgumentException("Expected 65-byte uncompressed EC point starting with 0x04");
        }
        byte[] x = Arrays.copyOfRange(bytes, 1, 1 + COORDINATE_LENGTH);
        byte[] y = Arrays.copyOfRange(bytes, 1 + COORDINATE_LENGTH, UNCOMPRESSED_POINT_LENGTH);
        ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
        return (ECPublicKey) EC_KEY_FACTORY.generatePublic(new ECPublicKeySpec(point, P256_SPEC));
    }

    private static ECParameterSpec loadP256Spec() {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance(EC);
            params.init(new ECGenParameterSpec(CURVE));
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to initialise P-256 parameters", e);
        }
    }

    private static KeyFactory loadEcKeyFactory() {
        try {
            return KeyFactory.getInstance(EC);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("EC KeyFactory not available", e);
        }
    }
}
