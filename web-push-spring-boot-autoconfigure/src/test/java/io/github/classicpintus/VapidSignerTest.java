package io.github.classicpintus;

import io.github.classicpintus.crypto.VapidSigner;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class VapidSignerTest {

    static String pubKeyBase64;
    static String privKeyBase64;
    static VapidSigner signer;

    @BeforeAll
    static void setup() throws Exception {
        KeyPair kp = TestKeyHelper.generateP256KeyPair();
        pubKeyBase64 = TestKeyHelper.encodePublicKey((ECPublicKey) kp.getPublic());
        privKeyBase64 = TestKeyHelper.encodePrivateKey((ECPrivateKey) kp.getPrivate());
        signer = new VapidSigner("mailto:test@test.com", pubKeyBase64, privKeyBase64);
    }

    @Test
    void buildAuthorizationHeader_hasCorrectFormat() {
        String header = signer.buildAuthorizationHeader("https://push.example.com/push/xyz");

        assertThat(header).startsWith("vapid t=");
        assertThat(header).contains(", k=" + pubKeyBase64);
    }

    @Test
    void buildAuthorizationHeader_jwtHasThreeParts() {
        String header = signer.buildAuthorizationHeader("https://push.example.com/push/xyz");
        assertThat(TestKeyHelper.decodeJwtParts(header)).hasSize(3);
    }

    @Test
    void buildAuthorizationHeader_payloadContainsCorrectClaims() {
        String header = signer.buildAuthorizationHeader("https://push.example.com/push/xyz");
        String payload = TestKeyHelper.decodeJwtPayload(header);

        assertThat(payload).contains("\"aud\":\"https://push.example.com\"");
        assertThat(payload).contains("\"sub\":\"mailto:test@test.com\"");
        assertThat(payload).contains("\"exp\":");
    }

    @Test
    void buildAuthorizationHeader_audienceStripsPath() {
        String header = signer.buildAuthorizationHeader("https://fcm.googleapis.com/fcm/send/abc123");
        String payload = TestKeyHelper.decodeJwtPayload(header);

        assertThat(payload).contains("\"aud\":\"https://fcm.googleapis.com\"");
    }

    @Test
    void buildAuthorizationHeader_cachesPerAudience() {
        String h1 = signer.buildAuthorizationHeader("https://push.example.com/push/aaa");
        String h2 = signer.buildAuthorizationHeader("https://push.example.com/push/bbb");
        String h3 = signer.buildAuthorizationHeader("https://other.example.com/push/aaa");

        assertThat(h1).isEqualTo(h2);
        assertThat(h1).isNotEqualTo(h3);
    }

    @Test
    void buildAuthorizationHeader_escapesQuotesInSubject() throws Exception {
        KeyPair kp = TestKeyHelper.generateP256KeyPair();
        VapidSigner trickySigner = new VapidSigner(
                "mailto:weird\"user@example.com",
                TestKeyHelper.encodePublicKey((ECPublicKey) kp.getPublic()),
                TestKeyHelper.encodePrivateKey((ECPrivateKey) kp.getPrivate()));

        String header = trickySigner.buildAuthorizationHeader("https://push.example.com/x");
        String payload = TestKeyHelper.decodeJwtPayload(header);

        assertThat(payload).contains("\"sub\":\"mailto:weird\\\"user@example.com\"");
        assertThat(TestKeyHelper.decodeJwtParts(header)).hasSize(3);
    }

    @Test
    void constructor_rejectsMalformedPrivateKey() {
        assertThatThrownBy(() -> new VapidSigner("mailto:t@t.com", pubKeyBase64, "***not-base64***"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void buildAuthorizationHeader_stripsDefaultHttpsPortFromAudience() {
        String payload = TestKeyHelper.decodeJwtPayload(
                signer.buildAuthorizationHeader("https://push.example.com:443/a"));
        assertThat(payload).contains("\"aud\":\"https://push.example.com\"");
    }

    @Test
    void buildAuthorizationHeader_keepsExplicitNonDefaultPortInAudience() {
        String payload = TestKeyHelper.decodeJwtPayload(
                signer.buildAuthorizationHeader("https://push.example.com:8443/a"));
        assertThat(payload).contains("\"aud\":\"https://push.example.com:8443\"");
    }

    @Test
    void buildAuthorizationHeader_omitsUserInfoFromAudience() {
        String payload = TestKeyHelper.decodeJwtPayload(
                signer.buildAuthorizationHeader("https://user:secret@push.example.com/a"));
        assertThat(payload).contains("\"aud\":\"https://push.example.com\"");
        assertThat(payload).doesNotContain("secret");
    }

    @Test
    void buildAuthorizationHeader_rejectsEndpointWithoutHost() {
        assertThatThrownBy(() -> signer.buildAuthorizationHeader("not-a-url"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
