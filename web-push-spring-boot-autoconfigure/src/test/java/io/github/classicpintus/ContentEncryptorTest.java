package io.github.classicpintus;

import io.github.classicpintus.crypto.ContentEncryptor;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ContentEncryptorTest {

    private final ContentEncryptor encryptor = new ContentEncryptor();

    @Test
    void encrypt_producesExpectedLength() throws Exception {
        String[] keys = TestKeyHelper.randomSubscriptionKeys();
        byte[] payload = "Hello!".getBytes(StandardCharsets.UTF_8);
        byte[] result = encryptor.encrypt(keys[0], keys[1], payload);

        int expected = 16 + 4 + 1 + 65 + (payload.length + 1 + 16);
        assertThat(result).hasSize(expected);
    }

    @Test
    void encrypt_idlenIs65AndKeyMarkerUncompressed() throws Exception {
        String[] keys = TestKeyHelper.randomSubscriptionKeys();
        byte[] result = encryptor.encrypt(keys[0], keys[1], "Test payload".getBytes(StandardCharsets.UTF_8));

        assertThat(result[20]).isEqualTo((byte) 65);
        assertThat(result[21]).isEqualTo((byte) 0x04);
    }

    @Test
    void encrypt_rsBytesReflectPayloadSize() throws Exception {
        String[] keys = TestKeyHelper.randomSubscriptionKeys();
        byte[] payload = "Hello!".getBytes(StandardCharsets.UTF_8);
        byte[] result = encryptor.encrypt(keys[0], keys[1], payload);

        int rs = ByteBuffer.wrap(result, 16, 4).getInt();
        assertThat(rs).isEqualTo(payload.length + 17);
    }

    @Test
    void encrypt_differentCallsProduceDifferentOutput() throws Exception {
        String[] keys = TestKeyHelper.randomSubscriptionKeys();
        byte[] payload = "Hello!".getBytes(StandardCharsets.UTF_8);
        byte[] r1 = encryptor.encrypt(keys[0], keys[1], payload);
        byte[] r2 = encryptor.encrypt(keys[0], keys[1], payload);

        assertThat(r1).isNotEqualTo(r2);
    }

    @Test
    void encrypt_rejectsMalformedBase64() {
        assertThatThrownBy(() -> encryptor.encrypt("***not-base64***", "AAAA", "x".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("p256dh");
    }

    @Test
    void encrypt_rejectsInvalidPublicKeyLength() {
        String tooShort = TestKeyHelper.base64Url(new byte[]{1, 2, 3});
        assertThatThrownBy(() -> encryptor.encrypt(tooShort, "AAAA", "x".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void encrypt_emptyPayload_rsIsAtLeastEighteen() throws Exception {
        String[] keys = TestKeyHelper.randomSubscriptionKeys();
        byte[] result = encryptor.encrypt(keys[0], keys[1], new byte[0]);

        int rs = ByteBuffer.wrap(result, 16, 4).getInt();
        assertThat(rs).isGreaterThanOrEqualTo(18);
    }

    @Test
    void encrypt_oversizedPayload_isRejected() throws Exception {
        String[] keys = TestKeyHelper.randomSubscriptionKeys();
        byte[] tooBig = new byte[4096];
        assertThatThrownBy(() -> encryptor.encrypt(keys[0], keys[1], tooBig))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("payload");
    }

    @Test
    void encrypt_rejectsPointOffSecp256r1Curve() throws Exception {
        String[] keys = TestKeyHelper.randomSubscriptionKeys();
        byte[] valid = Base64.getUrlDecoder().decode(keys[0]);
        // Flip the last y-byte so the point no longer satisfies the curve equation.
        valid[64] ^= 0x01;
        String tampered = TestKeyHelper.base64Url(valid);
        assertThatThrownBy(() -> encryptor.encrypt(tampered, keys[1], "x".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("curve");
    }

    @Test
    void encrypt_roundtripDecryptsToOriginalPayload() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair receiver = kpg.generateKeyPair();
        ECPublicKey receiverPub = (ECPublicKey) receiver.getPublic();
        ECPrivateKey receiverPriv = (ECPrivateKey) receiver.getPrivate();

        byte[] authSecret = new byte[16];
        new java.security.SecureRandom().nextBytes(authSecret);

        String p256dh = TestKeyHelper.base64Url(TestKeyHelper.uncompressedPoint(receiverPub));
        String auth = TestKeyHelper.base64Url(authSecret);

        byte[] plaintext = "When I grow up, I want to be a watermelon".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = encryptor.encrypt(p256dh, auth, plaintext);

        byte[] decrypted = decryptAes128Gcm(ciphertext, receiverPriv, receiverPub, authSecret);
        assertThat(decrypted).isEqualTo(plaintext);
    }

    private static byte[] decryptAes128Gcm(byte[] body, ECPrivateKey receiverPriv,
                                            ECPublicKey receiverPub, byte[] authSecret) throws Exception {
        ByteBuffer bb = ByteBuffer.wrap(body);
        byte[] salt = new byte[16];
        bb.get(salt);
        bb.getInt();
        int idlen = bb.get() & 0xFF;
        byte[] senderPubBytes = new byte[idlen];
        bb.get(senderPubBytes);
        byte[] encrypted = new byte[bb.remaining()];
        bb.get(encrypted);

        ECParameterSpec p256 = p256Spec();
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(senderPubBytes, 1, 33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(senderPubBytes, 33, 65));
        ECPublicKey senderPub = (ECPublicKey) KeyFactory.getInstance("EC")
                .generatePublic(new ECPublicKeySpec(new ECPoint(x, y), p256));

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(receiverPriv);
        ka.doPhase(senderPub, true);
        byte[] ecdhSecret = ka.generateSecret();

        byte[] receiverPubBytes = TestKeyHelper.uncompressedPoint(receiverPub);
        byte[] prkKey = hmac(authSecret, ecdhSecret);

        byte[] keyInfoLabel = "WebPush: info\0".getBytes(StandardCharsets.UTF_8);
        byte[] keyInfo = new byte[keyInfoLabel.length + 65 + 65];
        System.arraycopy(keyInfoLabel, 0, keyInfo, 0, keyInfoLabel.length);
        System.arraycopy(receiverPubBytes, 0, keyInfo, keyInfoLabel.length, 65);
        System.arraycopy(senderPubBytes, 0, keyInfo, keyInfoLabel.length + 65, 65);

        byte[] ikm = hkdfExpand(prkKey, keyInfo, 32);
        byte[] prk = hmac(salt, ikm);
        byte[] cek = hkdfExpand(prk, "Content-Encoding: aes128gcm\0".getBytes(StandardCharsets.UTF_8), 16);
        byte[] nonce = hkdfExpand(prk, "Content-Encoding: nonce\0".getBytes(StandardCharsets.UTF_8), 12);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, nonce));
        byte[] padded = cipher.doFinal(encrypted);
        int lastNonZero = padded.length - 1;
        while (lastNonZero >= 0 && padded[lastNonZero] == 0) lastNonZero--;
        assertThat(padded[lastNonZero]).isEqualTo((byte) 0x02);
        return Arrays.copyOfRange(padded, 0, lastNonZero);
    }

    private static byte[] hmac(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
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

    private static ECParameterSpec p256Spec() throws Exception {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        return params.getParameterSpec(ECParameterSpec.class);
    }
}
