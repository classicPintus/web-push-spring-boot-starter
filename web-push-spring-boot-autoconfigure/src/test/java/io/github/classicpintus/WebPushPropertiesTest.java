package io.github.classicpintus;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class WebPushPropertiesTest {

    @Test
    void retry_appliesDefaultsForNullValues() {
        WebPushProperties.Retry retry = new WebPushProperties.Retry(null, null, null);

        assertThat(retry.maxAttempts()).isZero();
        assertThat(retry.initialBackoff()).isEqualTo(Duration.ofSeconds(1));
        assertThat(retry.maxBackoff()).isEqualTo(Duration.ofMinutes(1));
    }

    @Test
    void retry_rejectsNegativeMaxAttempts() {
        assertThatThrownBy(() -> new WebPushProperties.Retry(-1, null, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("max-attempts");
    }

    @Test
    void retry_rejectsNonPositiveInitialBackoff() {
        assertThatThrownBy(() -> new WebPushProperties.Retry(1, Duration.ZERO, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("initial-backoff");
        assertThatThrownBy(() -> new WebPushProperties.Retry(1, Duration.ofSeconds(-1), null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("initial-backoff");
    }

    @Test
    void retry_rejectsMaxBackoffSmallerThanInitial() {
        assertThatThrownBy(() -> new WebPushProperties.Retry(
                1, Duration.ofSeconds(10), Duration.ofSeconds(1)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("max-backoff");
    }
}
