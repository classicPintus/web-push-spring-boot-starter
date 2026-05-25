package io.github.webpush;

import io.github.webpush.crypto.ContentEncryptor;
import io.github.webpush.crypto.VapidSigner;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;

final class WebPushServiceImpl implements WebPushService {

    static final String TTL_HEADER = "TTL";
    static final String CONTENT_ENCODING_AES128GCM = "aes128gcm";

    private final VapidSigner vapidSigner;
    private final ContentEncryptor contentEncryptor;
    private final WebPushProperties properties;
    private final RestClient restClient;

    WebPushServiceImpl(VapidSigner vapidSigner, ContentEncryptor contentEncryptor,
                       WebPushProperties properties, RestClient restClient) {
        this.vapidSigner = vapidSigner;
        this.contentEncryptor = contentEncryptor;
        this.properties = properties;
        this.restClient = restClient;
    }

    @Override
    public SendResult send(PushSubscription subscription, String payload) {
        Objects.requireNonNull(subscription, "subscription");
        Objects.requireNonNull(payload, "payload");
        return sendWithRetry(subscription, payload, properties.ttl());
    }

    private SendResult sendWithRetry(PushSubscription subscription, String payload, Duration ttl) {
        int maxAttempts = Math.max(1, properties.retry().maxAttempts() + 1);
        Duration backoff = properties.retry().initialBackoff();
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                HttpStatusCode status = sendOnce(subscription, payload, ttl);
                return SendResult.ok(subscription, status, attempt);
            } catch (RetryableException ex) {
                if (attempt == maxAttempts) {
                    return SendResult.failed(subscription, ex.status, ex.getCause(), attempt);
                }
                sleep(retryDelay(ex.retryAfter, backoff, attempt));
            } catch (NonRetryableException ex) {
                return SendResult.failed(subscription, ex.status, ex.getCause(), attempt);
            }
        }
        throw new IllegalStateException("unreachable");
    }

    private HttpStatusCode sendOnce(PushSubscription subscription, String payload, Duration ttl) {
        byte[] encryptedBody = contentEncryptor.encrypt(
                subscription.p256dh(), subscription.auth(), payload.getBytes(StandardCharsets.UTF_8));
        String authorization = vapidSigner.buildAuthorizationHeader(subscription.endpoint());
        try {
            return restClient.post()
                    .uri(subscription.endpoint())
                    .header(HttpHeaders.AUTHORIZATION, authorization)
                    .header(TTL_HEADER, String.valueOf(ttl.toSeconds()))
                    .header(HttpHeaders.CONTENT_ENCODING, CONTENT_ENCODING_AES128GCM)
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(encryptedBody)
                    .retrieve()
                    .toBodilessEntity()
                    .getStatusCode();
        } catch (HttpClientErrorException ex) {
            HttpStatusCode status = ex.getStatusCode();
            if (status.value() == HttpStatus.TOO_MANY_REQUESTS.value()) {
                throw new RetryableException(status, parseRetryAfter(ex), ex);
            }
            throw new NonRetryableException(status, ex);
        } catch (HttpServerErrorException ex) {
            HttpStatusCode status = ex.getStatusCode();
            if (status.value() == HttpStatus.SERVICE_UNAVAILABLE.value()) {
                throw new RetryableException(status, parseRetryAfter(ex), ex);
            }
            throw new NonRetryableException(status, ex);
        } catch (ResourceAccessException ex) {
            throw new RetryableException(null, null, ex);
        } catch (RestClientResponseException ex) {
            throw new NonRetryableException(ex.getStatusCode(), ex);
        } catch (RestClientException ex) {
            throw new NonRetryableException(null, ex);
        }
    }

    private static Duration parseRetryAfter(RestClientResponseException ex) {
        HttpHeaders headers = ex.getResponseHeaders();
        if (headers == null) return null;
        String value = headers.getFirst(HttpHeaders.RETRY_AFTER);
        if (value == null) return null;
        try {
            return Duration.ofSeconds(Long.parseLong(value.trim()));
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private static Duration retryDelay(Duration retryAfter, Duration initialBackoff, int attempt) {
        if (retryAfter != null && !retryAfter.isNegative()) return retryAfter;
        long millis = initialBackoff.toMillis() * (1L << (attempt - 1));
        long jitter = (long) (millis * 0.1 * Math.random());
        return Duration.ofMillis(millis + jitter);
    }

    private static void sleep(Duration duration) {
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Retry interrupted", e);
        }
    }

    private static final class RetryableException extends RuntimeException {
        private final HttpStatusCode status;
        private final Duration retryAfter;

        RetryableException(HttpStatusCode status, Duration retryAfter, Throwable cause) {
            super(cause == null ? "retryable" : cause.getMessage(), cause);
            this.status = status;
            this.retryAfter = retryAfter;
        }
    }

    private static final class NonRetryableException extends RuntimeException {
        private final HttpStatusCode status;

        NonRetryableException(HttpStatusCode status, Throwable cause) {
            super(cause == null ? "non-retryable" : cause.getMessage(), cause);
            this.status = status;
        }
    }
}
