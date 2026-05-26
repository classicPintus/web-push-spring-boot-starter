package io.github.classicpintus.webpush;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/**
 * Configuration properties for the web push starter.
 *
 * @param vapid VAPID identity (subject + EC P-256 keypair, RFC 8292).
 * @param ttl Default TTL for push messages (RFC 8030).
 * @param connectTimeout HTTP connection timeout to the push service.
 * @param readTimeout HTTP read timeout for the push service response.
 * @param retry Retry policy for transient failures (429, 503, network errors).
 */
@ConfigurationProperties(prefix = "webpush")
@Validated
public record WebPushProperties(
        @NotNull @Valid Vapid vapid,
        Duration ttl,
        Duration connectTimeout,
        Duration readTimeout,
        @Valid Retry retry
) {
    public WebPushProperties {
        if (ttl == null) ttl = Duration.ofDays(1);
        if (connectTimeout == null) connectTimeout = Duration.ofSeconds(5);
        if (readTimeout == null) readTimeout = Duration.ofSeconds(10);
        if (retry == null) retry = new Retry(null, null);
        if (ttl.isNegative()) throw new IllegalArgumentException("webpush.ttl must be non-negative");
        if (!connectTimeout.isPositive()) throw new IllegalArgumentException("webpush.connect-timeout must be positive");
        if (!readTimeout.isPositive()) throw new IllegalArgumentException("webpush.read-timeout must be positive");
    }

    /**
     * VAPID identity for signing the Authorization header.
     *
     * @param subject mailto: or https:// URI identifying the application server.
     * @param publicKey base64url-encoded uncompressed EC P-256 public key (65 bytes).
     * @param privateKey base64url-encoded EC P-256 private key scalar (32 bytes).
     */
    public record Vapid(
            @NotBlank @Pattern(regexp = "^(mailto:|https://).+",
                    message = "subject must be a mailto: or https:// URI") String subject,
            @NotBlank String publicKey,
            @NotBlank String privateKey
    ) {}

    /**
     * Retry policy for transient push-service failures.
     *
     * @param maxAttempts additional retry attempts after the initial send (0 disables retry).
     * @param initialBackoff backoff before the first retry; doubled per attempt when no Retry-After header is present.
     * @param maxBackoff upper bound on the wait between retries (caps both exponential backoff and Retry-After).
     */
    public record Retry(Integer maxAttempts, Duration initialBackoff, Duration maxBackoff) {
        public Retry {
            if (maxAttempts == null) maxAttempts = 0;
            if (initialBackoff == null) initialBackoff = Duration.ofSeconds(1);
            if (maxBackoff == null) maxBackoff = Duration.ofMinutes(1);
            if (maxAttempts < 0) throw new IllegalArgumentException("webpush.retry.max-attempts must be >= 0");
            if (!initialBackoff.isPositive())
                throw new IllegalArgumentException("webpush.retry.initial-backoff must be positive");
            if (!maxBackoff.isPositive())
                throw new IllegalArgumentException("webpush.retry.max-backoff must be positive");
            if (maxBackoff.compareTo(initialBackoff) < 0)
                throw new IllegalArgumentException("webpush.retry.max-backoff must be >= initial-backoff");
        }

        public Retry(Integer maxAttempts, Duration initialBackoff) {
            this(maxAttempts, initialBackoff, null);
        }
    }
}
