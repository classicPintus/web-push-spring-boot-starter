package io.github.classicpintus.webpush;

public interface WebPushService {

    SendResult send(PushSubscription subscription, String payload);
}
