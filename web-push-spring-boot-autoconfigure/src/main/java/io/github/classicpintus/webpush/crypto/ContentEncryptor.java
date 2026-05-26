package io.github.classicpintus.webpush.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Base64;

public final class ContentEncryptor {

    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final String AES = "AES";
    private static final String ECDH = "ECDH";
    private static final String HMAC_SHA256 = "HmacSHA256";

    private static final int SALT_LENGTH = 16;
    private static final int CEK_LENGTH = 16;
    private static final int NONCE_LENGTH = 12;
    private static final int IKM_LENGTH = 32;
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_TAG_BYTES = 16;
    private static final int RECORD_OVERHEAD = GCM_TAG_BYTES + 1;
    private static final int MIN_RECORD_SIZE = 18;
    private static final int MAX_RECORD_SIZE = 4096;
    private static final int MAX_PLAINTEXT_SIZE = MAX_RECORD_SIZE - RECORD_OVERHEAD;
    private static final byte RECORD_DELIMITER = 0x02;

    private static final byte[] KEY_INFO_LABEL = "WebPush: info\0".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CEK_INFO = singleByteInfo("Content-Encoding: aes128gcm");
    private static final byte[] NONCE_INFO = singleByteInfo("Content-Encoding: nonce");

    private static final SecureRandom RANDOM = new SecureRandom();

    public byte[] encrypt(String p256dhBase64Url, String authBase64Url, byte[] plaintext) {
        if (plaintext.length > MAX_PLAINTEXT_SIZE) {
            throw new IllegalArgumentException(
                    "payload exceeds maximum size of " + MAX_PLAINTEXT_SIZE + " bytes (RFC 8030 §7.2)");
        }
        byte[] userPublicKeyBytes = decodeBase64Url(p256dhBase64Url, "p256dh");
        byte[] authSecret = decodeBase64Url(authBase64Url, "auth");
        ECPublicKey userPublicKey = decodeUserPublicKey(userPublicKeyBytes);
        try {
            return encryptInternal(userPublicKeyBytes, authSecret, userPublicKey, plaintext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to encrypt web push payload", e);
        }
    }

    private byte[] encryptInternal(byte[] userPublicKeyBytes,
                                   byte[] authSecret,
                                   ECPublicKey userPublicKey,
                                   byte[] plaintext) throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(EcUtils.EC);
        kpg.initialize(EcUtils.p256Spec());
        KeyPair ephemeral = kpg.generateKeyPair();
        byte[] ephemeralPublicKeyBytes = EcUtils.uncompressedPoint((ECPublicKey) ephemeral.getPublic());

        KeyAgreement ka = KeyAgreement.getInstance(ECDH);
        ka.init(ephemeral.getPrivate());
        ka.doPhase(userPublicKey, true);
        byte[] ecdhSecret = ka.generateSecret();

        byte[] salt = new byte[SALT_LENGTH];
        RANDOM.nextBytes(salt);

        byte[] prkKey = hkdfExtract(authSecret, ecdhSecret);
        byte[] keyInfo = buildKeyInfo(userPublicKeyBytes, ephemeralPublicKeyBytes);
        byte[] ikm = hkdfExpand(prkKey, keyInfo, IKM_LENGTH);

        byte[] prk = hkdfExtract(salt, ikm);
        byte[] cek = hkdfExpand(prk, CEK_INFO, CEK_LENGTH);
        byte[] nonce = hkdfExpand(prk, NONCE_INFO, NONCE_LENGTH);

        byte[] paddedPlaintext = Arrays.copyOf(plaintext, plaintext.length + 1);
        paddedPlaintext[plaintext.length] = RECORD_DELIMITER;

        Cipher cipher = Cipher.getInstance(AES_GCM);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, AES), new GCMParameterSpec(GCM_TAG_BITS, nonce));
        byte[] ciphertext = cipher.doFinal(paddedPlaintext);

        int rs = Math.max(MIN_RECORD_SIZE, plaintext.length + RECORD_OVERHEAD);
        return ByteBuffer.allocate(SALT_LENGTH + 4 + 1 + EcUtils.UNCOMPRESSED_POINT_LENGTH + ciphertext.length)
                .put(salt)
                .putInt(rs)
                .put((byte) EcUtils.UNCOMPRESSED_POINT_LENGTH)
                .put(ephemeralPublicKeyBytes)
                .put(ciphertext)
                .array();
    }

    private static byte[] decodeBase64Url(String value, String fieldName) {
        try {
            return Base64.getUrlDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid base64url value for " + fieldName, e);
        }
    }

    private static ECPublicKey decodeUserPublicKey(byte[] bytes) {
        try {
            return EcUtils.decodeUncompressedPoint(bytes);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid p256dh public key", e);
        }
    }

    private static byte[] buildKeyInfo(byte[] userPublicKey, byte[] serverPublicKey) {
        int pointLen = EcUtils.UNCOMPRESSED_POINT_LENGTH;
        byte[] info = new byte[KEY_INFO_LABEL.length + pointLen + pointLen];
        System.arraycopy(KEY_INFO_LABEL, 0, info, 0, KEY_INFO_LABEL.length);
        System.arraycopy(userPublicKey, 0, info, KEY_INFO_LABEL.length, pointLen);
        System.arraycopy(serverPublicKey, 0, info, KEY_INFO_LABEL.length + pointLen, pointLen);
        return info;
    }

    private static byte[] singleByteInfo(String label) {
        byte[] bytes = label.getBytes(StandardCharsets.UTF_8);
        byte[] info = new byte[bytes.length + 1];
        System.arraycopy(bytes, 0, info, 0, bytes.length);
        return info;
    }

    private static byte[] hkdfExtract(byte[] salt, byte[] ikm)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(HMAC_SHA256);
        mac.init(new SecretKeySpec(salt, HMAC_SHA256));
        return mac.doFinal(ikm);
    }

    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(HMAC_SHA256);
        mac.init(new SecretKeySpec(prk, HMAC_SHA256));
        int hashLen = mac.getMacLength();
        int blocks = (length + hashLen - 1) / hashLen;
        byte[] out = new byte[blocks * hashLen];
        byte[] previous = new byte[0];
        for (int i = 1; i <= blocks; i++) {
            mac.update(previous);
            mac.update(info);
            mac.update((byte) i);
            previous = mac.doFinal();
            System.arraycopy(previous, 0, out, (i - 1) * hashLen, hashLen);
        }
        return Arrays.copyOf(out, length);
    }

}
