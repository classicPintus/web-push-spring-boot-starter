# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & test

```bash
./mvnw test                                   # esegui tutti i test
./mvnw -pl web-push-spring-boot-autoconfigure test   # solo modulo autoconfigure
./mvnw -pl web-push-spring-boot-autoconfigure test -Dtest=VapidSignerTest        # singola classe
./mvnw -pl web-push-spring-boot-autoconfigure test -Dtest=VapidSignerTest#methodName  # singolo metodo
./mvnw -B verify                              # build completa
```

Target: Java 25, Spring Boot 4.0.6. Niente BouncyCastle — solo JCA/JDK.

## Release (Maven Central)

```bash
./mvnw versions:set -DnewVersion=X.Y.Z
./mvnw -Prelease clean deploy                                          # firma GPG + upload
./mvnw -Prelease -Dgpg.skip=true -Dcentral.skipPublishing=true clean deploy  # dry-run
```

Richiede server id `central` in `~/.m2/settings.xml` e chiave GPG locale. GroupId pubblicato: `io.github.classicpintus`.

## Architettura

Maven multi-module:

- `web-push-spring-boot-autoconfigure` — codice, auto-config, crypto, test;
- `web-push-spring-boot-starter` — solo POM, aggrega autoconfigure + `spring-boot-starter-restclient`.

### Flusso send

`WebPushServiceImpl.send` → `sendWithRetry` → `sendOnce`:

1. `ContentEncryptor.encrypt(p256dh, auth, payload)` — ECDH P-256 + HKDF SHA-256 + AES-128-GCM (RFC 8188 `aes128gcm`).
2. `VapidSigner.buildAuthorizationHeader(endpoint)` — JWT ES256 firmato + cache per audience (origin dell'endpoint).
3. `RestClient` POST con header `Authorization`, `TTL`, `Content-Encoding: aes128gcm`, body `application/octet-stream`.

### Retry / classificazione errori (in `WebPushServiceImpl`)

- Retryable: `HTTP 429` (legge `Retry-After`), `HTTP 503`, `ResourceAccessException` (errori di rete).
- Non retryable: ogni altro 4xx/5xx → `SendResult.failed` con lo status code.
- Backoff: esponenziale `initialBackoff * 2^(attempt-1)` + jitter 10%, salvo `Retry-After` esplicito.
- `SendResult.isSubscriptionExpired()` → `true` se status 404 o 410 (il consumer deve rimuovere la subscription).

### Bean registrati da `WebPushAutoConfiguration`

Attivo se `RestClient` è sul classpath e `webpush.enabled != false`. Tutti i bean sono `@ConditionalOnMissingBean`:

- `VapidSigner`, `ContentEncryptor`, `WebPushService`;
- `RestClient` con nome bean `webPushRestClient` (basato su `JdkClientHttpRequestFactory` con `connect-timeout` / `read-timeout` dalle properties). Per override, definire un bean con lo stesso nome.

Auto-configuration registrata in `src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`.

### Properties (`WebPushProperties`, prefix `webpush`)

`enabled`, `vapid.{subject,public-key,private-key}`, `ttl`, `connect-timeout`, `read-timeout`, `retry.{max-attempts,initial-backoff}`. Chiavi VAPID in base64url: public = punto EC non compresso 65 byte, private = scalar 32 byte.

## Doppio package (importante)

Il sorgente contiene **due copie parallele** del codice:

- `io.github.webpush.*`
- `io.github.classicpintus.*`

L'unica auto-config registrata è `io.github.classicpintus.WebPushAutoConfiguration` (vedi file `.imports`) — quindi `io.github.classicpintus` è il package "vivo". I file sotto `io.github.webpush` sono un residuo del rename verso il groupId Maven Central. Quando modifichi codice, **applica la modifica in entrambe le copie** finché il package legacy non viene rimosso, oppure verifica con l'utente quale eliminare. Lo stesso vale per i test in `src/test/java/io/github/{webpush,classicpintus}/`.
