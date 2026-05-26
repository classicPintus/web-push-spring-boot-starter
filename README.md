# Project Context

This project is a custom Spring Boot starter for sending Web Push notifications from Spring Boot applications.

## Purpose

Provide a ready-to-use dependency to include in a Spring Boot app to get a `WebPushService` bean configured via properties.

The service:

- encrypts the payload according to Web Push encryption (`aes128gcm`);
- signs requests with VAPID;
- sends the notification to the browser's push service via `RestClient`;
- returns a `SendResult` with outcome, HTTP status, attempts and any error.

## Structure

The project is a Maven multi-module:

- `web-push-spring-boot-autoconfigure`: contains the code, auto-configuration, properties, service and crypto;
- `web-push-spring-boot-starter`: starter module, POM only, aggregates autoconfigure and the required dependencies;
- `pom.xml`: parent POM.

## Main API

Public package: `io.github.classicpintus`.

Main classes:

- `WebPushService`: interface to use in consumer applications;
- `WebPushServiceImpl`: internal implementation;
- `PushSubscription`: record with `endpoint`, `p256dh`, `auth`;
- `SendResult`: send result;
- `WebPushProperties`: configuration under prefix `webpush`;
- `WebPushAutoConfiguration`: registers the beans if `RestClient` is available and `webpush.enabled` is not disabled.

Expected usage:

```java
webPushService.send(subscription, payload);
```

## Configuration

Properties prefix:

```yaml
webpush:
  enabled: true
  vapid:
    subject: mailto:info@example.com
    public-key: ${VAPID_PUBLIC_KEY}
    private-key: ${VAPID_PRIVATE_KEY}
  ttl: 1d
  connect-timeout: 5s
  read-timeout: 10s
  retry:
    max-attempts: 0
    initial-backoff: 1s
```

VAPID keys are EC P-256 in base64url:

- public key: uncompressed point, 65 bytes;
- private key: scalar, 32 bytes.

## Send

`WebPushServiceImpl`:

1. encrypts the payload with `ContentEncryptor`;
2. builds the VAPID `Authorization` header with `VapidSigner`;
3. sends a POST to `subscription.endpoint()`;
4. sets headers `TTL` and `Content-Encoding: aes128gcm`;
5. applies retry on transient errors.

Retry:

- `429 Too Many Requests`: retryable;
- `503 Service Unavailable`: retryable;
- `ResourceAccessException`: retryable;
- other client/server errors: non-retryable.

`SendResult.isSubscriptionExpired()` considers subscriptions with status `404` or `410` as expired.

## Crypto

The crypto is implemented with JCA/JDK, without BouncyCastle.

Components:

- `VapidSigner`: generates and caches VAPID headers per audience;
- `ContentEncryptor`: ECDH P-256, HKDF SHA-256, AES-128-GCM;
- `EcUtils`: utilities for curves and EC point encoding.

## Tests

Tests located in the autoconfigure module:

- auto-configuration;
- VAPID signer;
- content encryption;
- service implementation;
- FCM integration.

Typical command:

```bash
./mvnw test
```

## Publishing to Maven Central

Local prerequisites:

- namespace `io.github.classicpintus` verified on https://central.sonatype.com;
- Central Portal token in `~/.m2/settings.xml` with server id `central`;
- GPG key available locally.

Example `~/.m2/settings.xml`:

```xml
<settings>
  <servers>
    <server>
      <id>central</id>
      <username>...</username>
      <password>...</password>
    </server>
  </servers>
</settings>
```

Manual release:

```bash
./mvnw versions:set -DnewVersion=0.1.0
./mvnw -Prelease clean deploy
```

Dry-run without signing and without upload:

```bash
./mvnw -Prelease -Dgpg.skip=true -Dcentral.skipPublishing=true clean deploy
```

## Operational notes

- Current target: Spring Boot `4.0.6`, Java `25`.
- Auto-configuration registered in `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`.
