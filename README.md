# Project Context

Questo progetto e' un custom Spring Boot starter per inviare notifiche Web Push da applicazioni Spring Boot.

## Scopo

Fornire una dipendenza pronta da includere in un'app Spring Boot per ottenere un bean `WebPushService` configurato via properties.

Il servizio:

- cifra il payload secondo Web Push encryption (`aes128gcm`);
- firma le richieste con VAPID;
- invia la notifica al push service del browser tramite `RestClient`;
- restituisce un `SendResult` con esito, status HTTP, tentativi e errore eventuale.

## Struttura

Il progetto e' un Maven multi-module:

- `web-push-spring-boot-autoconfigure`: contiene codice, auto-configuration, properties, servizio e crypto;
- `web-push-spring-boot-starter`: modulo starter, solo POM, aggrega autoconfigure e dipendenze necessarie;
- `pom.xml`: parent POM.

## API principale

Package pubblico: `io.github.webpush`.

Classi principali:

- `WebPushService`: interfaccia da usare nelle applicazioni consumer;
- `WebPushServiceImpl`: implementazione interna;
- `PushSubscription`: record con `endpoint`, `p256dh`, `auth`;
- `SendResult`: risultato dell'invio;
- `WebPushProperties`: configurazione sotto prefisso `webpush`;
- `WebPushAutoConfiguration`: registra i bean se `RestClient` e' disponibile e `webpush.enabled` non e' disabilitato.

Uso atteso:

```java
webPushService.send(subscription, payload);
```

## Configurazione

Prefix properties:

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

Le chiavi VAPID sono EC P-256 in base64url:

- public key: punto non compresso, 65 byte;
- private key: scalar, 32 byte.

## Invio

`WebPushServiceImpl`:

1. cifra il payload con `ContentEncryptor`;
2. crea header `Authorization` VAPID con `VapidSigner`;
3. invia POST verso `subscription.endpoint()`;
4. imposta header `TTL` e `Content-Encoding: aes128gcm`;
5. applica retry su errori transienti.

Retry:

- `429 Too Many Requests`: retryable;
- `503 Service Unavailable`: retryable;
- `ResourceAccessException`: retryable;
- altri errori client/server: non retryable.

`SendResult.isSubscriptionExpired()` considera scadute le subscription con status `404` o `410`.

## Crypto

La crypto e' implementata con JCA/JDK, senza BouncyCastle.

Componenti:

- `VapidSigner`: genera e mette in cache header VAPID per audience;
- `ContentEncryptor`: ECDH P-256, HKDF SHA-256, AES-128-GCM;
- `EcUtils`: utilita' per curve e codifica punti EC.

## Test

Test presenti nel modulo autoconfigure:

- auto-configuration;
- VAPID signer;
- content encryption;
- service implementation;
- integrazione FCM.

Comando tipico:

```bash
./mvnw test
```

## Pubblicazione Maven Central

Prerequisiti locali:

- namespace `io.github.classicpintus` verificato su https://central.sonatype.com;
- token Central Portal in `~/.m2/settings.xml` con server id `central`;
- chiave GPG disponibile localmente.

Esempio `~/.m2/settings.xml`:

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

Release manuale:

```bash
./mvnw versions:set -DnewVersion=0.1.0
./mvnw -Prelease clean deploy
```

Dry-run senza firma e senza upload:

```bash
./mvnw -Prelease -Dgpg.skip=true -Dcentral.skipPublishing=true clean deploy
```

## Note operative

- Target attuale: Spring Boot `4.0.6`, Java `25`.
- Auto-configuration registrata in `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`.
