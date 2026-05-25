package io.github.classicpintus;

import io.github.classicpintus.crypto.ContentEncryptor;
import io.github.classicpintus.crypto.VapidSigner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class WebPushServiceImplTest {

    private static final String ENDPOINT = "https://push.example.com/push/abc";

    String vapidPublicKey;
    String vapidPrivateKey;
    MockRestServiceServer mockServer;
    WebPushServiceImpl service;
    PushSubscription subscription;

    @BeforeEach
    void setup() throws Exception {
        KeyPair kp = TestKeyHelper.generateP256KeyPair();
        vapidPublicKey = TestKeyHelper.encodePublicKey((ECPublicKey) kp.getPublic());
        vapidPrivateKey = TestKeyHelper.encodePrivateKey((ECPrivateKey) kp.getPrivate());

        service = buildService(defaultProps());
        subscription = TestKeyHelper.randomSubscription(ENDPOINT);
    }

    @Test
    void send_postsToEndpointWithRequiredHeaders() {
        mockServer.expect(requestTo(ENDPOINT))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header(HttpHeaders.CONTENT_ENCODING, "aes128gcm"))
                .andExpect(header("TTL", "86400"))
                .andExpect(header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_OCTET_STREAM_VALUE))
                .andRespond(withSuccess());

        SendResult result = service.send(subscription, "Hello!");

        assertThat(result.success()).isTrue();
        assertThat(result.statusCode().value()).isEqualTo(200);
        assertThat(result.attempts()).isEqualTo(1);
        mockServer.verify();
    }

    @Test
    void send_includesAuthorizationVapidAndKey() {
        mockServer.expect(requestTo(ENDPOINT))
                .andExpect(header(HttpHeaders.AUTHORIZATION, startsWith("vapid t=")))
                .andExpect(header(HttpHeaders.AUTHORIZATION, containsString(",k=" + vapidPublicKey)))
                .andRespond(withSuccess());

        assertThat(service.send(subscription, "Hello!").success()).isTrue();
        mockServer.verify();
    }

    @Test
    void send_writesEncryptedBody() {
        mockServer.expect(requestTo(ENDPOINT))
                .andExpect(request -> {
                    byte[] body = ((MockClientHttpRequest) request).getBodyAsBytes();
                    assertThat(body.length).isGreaterThanOrEqualTo(16 + 4 + 1 + 65 + 23);
                    assertThat(body[20]).isEqualTo((byte) 65);
                    assertThat(body[21]).isEqualTo((byte) 0x04);
                })
                .andRespond(withSuccess());

        assertThat(service.send(subscription, "Hello!").success()).isTrue();
        mockServer.verify();
    }

    @Test
    void send_on410Gone_returnsFailedResultMarkedExpired() {
        mockServer.expect(requestTo(ENDPOINT)).andRespond(withStatus(HttpStatus.GONE));

        SendResult result = service.send(subscription, "Hello!");

        assertThat(result.success()).isFalse();
        assertThat(result.statusCode().value()).isEqualTo(410);
        assertThat(result.isSubscriptionExpired()).isTrue();
    }

    @Test
    void send_on404NotFound_returnsFailedResultMarkedExpired() {
        mockServer.expect(requestTo(ENDPOINT)).andRespond(withStatus(HttpStatus.NOT_FOUND));

        SendResult result = service.send(subscription, "Hello!");

        assertThat(result.success()).isFalse();
        assertThat(result.statusCode().value()).isEqualTo(404);
        assertThat(result.isSubscriptionExpired()).isTrue();
    }

    @Test
    void send_on500_returnsFailedResultWithStatus() {
        mockServer.expect(requestTo(ENDPOINT)).andRespond(withServerError());

        SendResult result = service.send(subscription, "Hello!");

        assertThat(result.success()).isFalse();
        assertThat(result.statusCode().value()).isEqualTo(500);
        assertThat(result.isSubscriptionExpired()).isFalse();
    }

    @Test
    void send_on429_isRetriedUntilSuccess() {
        service = buildService(propsWithRetry(2, Duration.ofMillis(1)));

        mockServer.expect(requestTo(ENDPOINT)).andRespond(withStatus(HttpStatus.TOO_MANY_REQUESTS));
        mockServer.expect(requestTo(ENDPOINT)).andRespond(withStatus(HttpStatus.TOO_MANY_REQUESTS));
        mockServer.expect(requestTo(ENDPOINT)).andRespond(withSuccess());

        SendResult result = service.send(subscription, "Hello!");

        assertThat(result.success()).isTrue();
        assertThat(result.attempts()).isEqualTo(3);
        mockServer.verify();
    }

    @Test
    void send_on429_exhaustsRetriesAndReturnsFailedResult() {
        service = buildService(propsWithRetry(1, Duration.ofMillis(1)));

        mockServer.expect(requestTo(ENDPOINT)).andRespond(withStatus(HttpStatus.TOO_MANY_REQUESTS));
        mockServer.expect(requestTo(ENDPOINT)).andRespond(withStatus(HttpStatus.TOO_MANY_REQUESTS));

        SendResult result = service.send(subscription, "Hello!");

        assertThat(result.success()).isFalse();
        assertThat(result.statusCode().value()).isEqualTo(429);
        assertThat(result.attempts()).isEqualTo(2);
    }

    @Test
    void send_nullSubscription_throws() {
        assertThatThrownBy(() -> service.send(null, "x"))
                .isInstanceOf(NullPointerException.class);
    }

    private WebPushServiceImpl buildService(WebPushProperties props) {
        VapidSigner signer = new VapidSigner("mailto:test@test.com", vapidPublicKey, vapidPrivateKey);
        RestClient.Builder builder = RestClient.builder();
        mockServer = MockRestServiceServer.bindTo(builder).build();
        return new WebPushServiceImpl(signer, new ContentEncryptor(), props, builder.build());
    }

    private WebPushProperties defaultProps() {
        return new WebPushProperties(
                new WebPushProperties.Vapid("mailto:test@test.com", vapidPublicKey, vapidPrivateKey),
                null, null, null, null);
    }

    private WebPushProperties propsWithRetry(int maxAttempts, Duration initialBackoff) {
        return new WebPushProperties(
                new WebPushProperties.Vapid("mailto:test@test.com", vapidPublicKey, vapidPrivateKey),
                null, null, null, new WebPushProperties.Retry(maxAttempts, initialBackoff));
    }
}
