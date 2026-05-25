package io.github.webpush;

public interface WebPushService {

    SendResult send(PushSubscription subscription, String payload);
}
