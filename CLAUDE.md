# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & test

```bash
./mvnw test                                   # run all tests
./mvnw -pl web-push-spring-boot-autoconfigure test   # autoconfigure module only
./mvnw -pl web-push-spring-boot-autoconfigure test -Dtest=VapidSignerTest        # single class
./mvnw -pl web-push-spring-boot-autoconfigure test -Dtest=VapidSignerTest#methodName  # single method
./mvnw -B verify                              # full build
```

Target: Java 25, Spring Boot 4.0.6. No BouncyCastle — only JCA/JDK.

## Release (Maven Central)

```bash
./mvnw versions:set -DnewVersion=X.Y.Z
./mvnw -Prelease clean deploy                                          # GPG sign + upload
./mvnw -Prelease -Dgpg.skip=true -Dcentral.skipPublishing=true clean deploy  # dry-run
```

Requires server id `central` in `~/.m2/settings.xml` and a local GPG key. Published groupId: `io.github.classicpintus`.

## Architecture

Maven multi-module:

- `web-push-spring-boot-autoconfigure` — code, auto-config, crypto, tests;
- `web-push-spring-boot-starter` — POM only, aggregates autoconfigure + `spring-boot-starter-restclient`.

### Send flow

`WebPushServiceImpl.send` → `sendWithRetry` → `sendOnce`:

1. `ContentEncryptor.encrypt(p256dh, auth, payload)` — ECDH P-256 + HKDF SHA-256 + AES-128-GCM (RFC 8188 `aes128gcm`).
2. `VapidSigner.buildAuthorizationHeader(endpoint)` — signed ES256 JWT + per-audience cache (endpoint origin).
3. `RestClient` POST with headers `Authorization`, `TTL`, `Content-Encoding: aes128gcm`, body `application/octet-stream`.

### Retry / error classification (in `WebPushServiceImpl`)

- Retryable: `HTTP 429` (reads `Retry-After`), `HTTP 503`, `ResourceAccessException` (network errors).
- Non-retryable: any other 4xx/5xx → `SendResult.failed` with the status code.
- Backoff: exponential `initialBackoff * 2^(attempt-1)` + 10% jitter, unless an explicit `Retry-After` is provided.
- `SendResult.isSubscriptionExpired()` → `true` if status is 404 or 410 (the consumer must remove the subscription).

### Beans registered by `WebPushAutoConfiguration`

Active if `RestClient` is on the classpath and `webpush.enabled != false`. All beans are `@ConditionalOnMissingBean`:

- `VapidSigner`, `ContentEncryptor`, `WebPushService`;
- `RestClient` with bean name `webPushRestClient` (based on `JdkClientHttpRequestFactory` with `connect-timeout` / `read-timeout` from properties). To override, define a bean with the same name.

Auto-configuration registered in `src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` as `io.github.classicpintus.webpush.WebPushAutoConfiguration`.

### Properties (`WebPushProperties`, prefix `webpush`)

`enabled`, `vapid.{subject,public-key,private-key}`, `ttl`, `connect-timeout`, `read-timeout`, `retry.{max-attempts,initial-backoff}`. VAPID keys in base64url: public = uncompressed EC point, 65 bytes; private = scalar, 32 bytes.
