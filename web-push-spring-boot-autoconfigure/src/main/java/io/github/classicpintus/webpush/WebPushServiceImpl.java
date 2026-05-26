package io.github.classicpintus.webpush;

import io.github.classicpintus.webpush.crypto.ContentEncryptor;
import io.github.classicpintus.webpush.crypto.VapidSigner;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.web.client.*;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;
import java.util.Objects;
import java.util.concurrent.ThreadLocalRandom;

public final class WebPushServiceImpl implements WebPushService {

    static final String TTL_HEADER = "TTL";
    static final String CONTENT_ENCODING_AES128GCM = "aes128gcm";

    private final VapidSigner vapidSigner;
    private final ContentEncryptor contentEncryptor;
    private final WebPushProperties properties;
    private final RestClient restClient;

    public WebPushServiceImpl(VapidSigner vapidSigner, ContentEncryptor contentEncryptor,
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
        WebPushProperties.Retry retry = properties.retry();
        int maxAttempts = retry.maxAttempts() + 1;
        Duration backoff = retry.initialBackoff();
        Duration maxBackoff = retry.maxBackoff();
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                HttpStatusCode status = sendOnce(subscription, payload, ttl);
                return SendResult.ok(subscription, status, attempt);
            } catch (RetryableException ex) {
                if (attempt == maxAttempts) {
                    return SendResult.failed(subscription, ex.status, ex.getCause(), attempt);
                }
                if (!sleep(retryDelay(ex.retryAfter, backoff, maxBackoff, attempt))) {
                    return SendResult.failed(subscription, ex.status, ex.getCause(), attempt);
                }
            } catch (NonRetryableException ex) {
                return SendResult.failed(subscription, ex.status, ex.getCause(), attempt);
            }
        }
        throw new IllegalStateException("unreachable");
    }

    private HttpStatusCode sendOnce(PushSubscription subscription, String payload, Duration ttl) {
        byte[] encryptedBody;
        String authorization;
        try {
            encryptedBody = contentEncryptor.encrypt(
                    subscription.p256dh(), subscription.auth(), payload.getBytes(StandardCharsets.UTF_8));
            authorization = vapidSigner.buildAuthorizationHeader(subscription.endpoint());
        } catch (IllegalArgumentException | IllegalStateException ex) {
            throw new NonRetryableException(null, ex);
        }
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

    static Duration parseRetryAfter(RestClientResponseException ex) {
        HttpHeaders headers = ex.getResponseHeaders();
        if (headers == null) return null;
        String value = headers.getFirst(HttpHeaders.RETRY_AFTER);
        if (value == null) return null;
        return parseRetryAfterValue(value.trim());
    }

    static Duration parseRetryAfterValue(String value) {
        try {
            long seconds = Long.parseLong(value);
            return seconds < 0 ? null : Duration.ofSeconds(seconds);
        } catch (NumberFormatException ignored) {
            // RFC 7231 also allows an HTTP-date.
        }
        try {
            ZonedDateTime when = ZonedDateTime.parse(value, java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME);
            Duration delta = Duration.between(ZonedDateTime.now(when.getZone()), when);
            return delta.isNegative() ? Duration.ZERO : delta;
        } catch (DateTimeParseException ignored) {
            return null;
        }
    }

    static Duration retryDelay(Duration retryAfter, Duration initialBackoff, Duration maxBackoff, int attempt) {
        long capMillis = Math.max(1L, maxBackoff.toMillis());
        if (retryAfter != null && !retryAfter.isNegative()) {
            return Duration.ofMillis(Math.min(retryAfter.toMillis(), capMillis));
        }
        int shift = Math.min(Math.max(0, attempt - 1), 30);
        long base = initialBackoff.toMillis();
        long expMillis = base > 0 && shift > 0 && base > Long.MAX_VALUE >> shift
                ? capMillis
                : base << shift;
        long bounded = Math.min(expMillis, capMillis);
        long jitter = (long) (bounded * 0.1 * ThreadLocalRandom.current().nextDouble());
        return Duration.ofMillis(Math.min(bounded + jitter, capMillis));
    }

    private static boolean sleep(Duration duration) {
        try {
            Thread.sleep(Math.max(0L, duration.toMillis()));
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
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
