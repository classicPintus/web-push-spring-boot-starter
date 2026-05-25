package io.github.webpush;

import org.springframework.http.HttpStatusCode;

public record SendResult(
        PushSubscription subscription,
        boolean success,
        HttpStatusCode statusCode,
        int attempts,
        Throwable error) {

    public static SendResult ok(PushSubscription subscription, HttpStatusCode statusCode, int attempts) {
        return new SendResult(subscription, true, statusCode, attempts, null);
    }

    public static SendResult failed(PushSubscription subscription, HttpStatusCode statusCode,
                                    Throwable error, int attempts) {
        return new SendResult(subscription, false, statusCode, attempts, error);
    }

    public boolean isSubscriptionExpired() {
        if (statusCode == null) return false;
        int v = statusCode.value();
        return v == 404 || v == 410;
    }
}
