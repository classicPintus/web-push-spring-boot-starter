package io.github.classicpintus;

public interface WebPushService {

    SendResult send(PushSubscription subscription, String payload);
}
