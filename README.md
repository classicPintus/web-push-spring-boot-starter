# Project Context

This project is a custom Spring Boot starter for sending Web Push notifications from Spring Boot applications.

## Purpose

Provide a ready-to-use dependency to include in a Spring Boot app to get a `WebPushService` bean configured via properties.

The service:

- encrypts the payload according to Web Push encryption (`aes128gcm`);
- signs requests with VAPID;
- sends the notification to the browser's push service via `RestClient`;
- returns a `SendResult` with outcome, HTTP status, attempts and any error.

## Getting started

Requires Spring Boot 4.0.x and Java 25.

### 1. Add the dependency

Maven:

```xml
<dependency>
    <groupId>io.github.classicpintus</groupId>
    <artifactId>web-push-spring-boot-starter</artifactId>
    <version>0.2.0</version>
</dependency>
```

Gradle (Kotlin DSL):

```kotlin
implementation("io.github.classicpintus:web-push-spring-boot-starter:0.2.0")
```

The starter pulls in `web-push-spring-boot-autoconfigure` and `spring-boot-starter-restclient`.

### 2. Generate VAPID keys

If you don't already have a VAPID keypair, generate one (P-256, base64url encoded — public = uncompressed 65-byte point, private = 32-byte scalar). For example with the `web-push` Node CLI:

```bash
npx web-push generate-vapid-keys
```

The public key must also be sent to the browser to subscribe the user via `PushManager.subscribe({ userVisibleOnly: true, applicationServerKey })`.

### 3. Configure `application.yml`

```yaml
webpush:
  vapid:
    subject: mailto:info@example.com
    public-key: ${VAPID_PUBLIC_KEY}
    private-key: ${VAPID_PRIVATE_KEY}
  ttl: 1d                    # optional, default 1d
  connect-timeout: 5s        # optional
  read-timeout: 10s          # optional
  retry:
    max-attempts: 3          # optional, default 0 (no retry)
    initial-backoff: 1s      # optional
```

Set `webpush.enabled: false` to disable auto-configuration.

### 4. Inject and use `WebPushService`

```java
import io.github.classicpintus.webpush.PushSubscription;
import io.github.classicpintus.webpush.SendResult;
import io.github.classicpintus.webpush.WebPushService;
import org.springframework.stereotype.Service;

@Service
public class NotificationService {

    private final WebPushService webPushService;

    public NotificationService(WebPushService webPushService) {
        this.webPushService = webPushService;
    }

    public void notify(String endpoint, String p256dh, String auth, String payload) {
        PushSubscription subscription = new PushSubscription(endpoint, p256dh, auth);
        SendResult result = webPushService.send(subscription, payload);

        if (result.isSubscriptionExpired()) {
            // 404 / 410: remove the subscription from your storage
        } else if (!result.success()) {
            // inspect result.statusCode() and result.error()
        }
    }
}
```

The `endpoint`, `p256dh`, and `auth` fields come from the `PushSubscription` object the browser produces on the client side.

### 5. Override the `RestClient` (optional)

To customize the HTTP client, declare a `RestClient` bean named `webPushRestClient`:

```java
@Bean
RestClient webPushRestClient(RestClient.Builder builder) {
    return builder
            .requestFactory(/* your factory */)
            .build();
}
```

## Structure

The project is a Maven multi-module:

- `web-push-spring-boot-autoconfigure`: contains the code, auto-configuration, properties, service and crypto;
- `web-push-spring-boot-starter`: starter module, POM only, aggregates autoconfigure and the required dependencies;
- `pom.xml`: parent POM.

## Main API

Public package: `io.github.classicpintus.webpush`.

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
