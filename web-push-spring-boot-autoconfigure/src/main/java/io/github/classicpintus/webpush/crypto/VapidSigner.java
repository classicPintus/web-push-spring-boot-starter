package io.github.classicpintus.webpush.crypto;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECPrivateKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public final class VapidSigner {

    private static final String ES256 = "ES256";
    private static final String SIGNATURE_ALG = "SHA256withECDSA";
    private static final String JWT_TYP = "JWT";
    private static final String AUTH_SCHEME = "vapid t=";
    private static final String AUTH_KEY_PARAM = ", k=";

    private static final Duration JWT_LIFETIME = Duration.ofHours(12);
    private static final Duration CACHE_REFRESH_MARGIN = Duration.ofMinutes(5);
    private static final int DER_HEADER_BYTES = 4;
    private static final int RAW_SIGNATURE_LENGTH = 64;

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String JWT_HEADER = base64UrlEncode(toJsonBytes(Map.of("typ", JWT_TYP, "alg", ES256)));

    private final ECPrivateKey privateKey;
    private final String publicKeyBase64Url;
    private final String subject;
    private final Clock clock;
    private final ConcurrentMap<String, CachedHeader> cache = new ConcurrentHashMap<>();

    public VapidSigner(String subject, String publicKeyBase64Url, String privateKeyBase64Url) {
        this(subject, publicKeyBase64Url, privateKeyBase64Url, Clock.systemUTC());
    }

    VapidSigner(String subject, String publicKeyBase64Url, String privateKeyBase64Url, Clock clock) {
        this.subject = subject;
        this.publicKeyBase64Url = publicKeyBase64Url;
        this.clock = clock;
        this.privateKey = loadPrivateKey(privateKeyBase64Url);
    }

    public String buildAuthorizationHeader(String endpoint) {
        String audience = extractAudience(endpoint);
        long now = clock.instant().getEpochSecond();
        CachedHeader cached = cache.get(audience);
        if (cached != null && cached.expiresAt - now > CACHE_REFRESH_MARGIN.toSeconds()) {
            return cached.header;
        }
        long exp = now + JWT_LIFETIME.toSeconds();
        String header = sign(audience, exp);
        cache.put(audience, new CachedHeader(header, exp));
        return header;
    }

    static String extractAudience(String endpoint) {
        try {
            URI uri = new URI(endpoint);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (scheme == null || host == null) {
                throw new IllegalArgumentException("Endpoint must be an absolute URL: " + endpoint);
            }
            String lowerScheme = scheme.toLowerCase();
            int port = uri.getPort();
            boolean defaultPort = port == -1
                    || (port == 443 && "https".equals(lowerScheme))
                    || (port == 80 && "http".equals(lowerScheme));
            return defaultPort
                    ? lowerScheme + "://" + host
                    : lowerScheme + "://" + host + ":" + port;
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid endpoint URL: " + endpoint, e);
        }
    }

    private String sign(String audience, long exp) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("aud", audience);
        claims.put("exp", exp);
        claims.put("sub", subject);
        String payloadEncoded = base64UrlEncode(toJsonBytes(claims));
        String signingInput = JWT_HEADER + "." + payloadEncoded;
        byte[] rawSignature = derToJoseRaw(signRaw(signingInput));
        String jwt = signingInput + "." + base64UrlEncode(rawSignature);
        return AUTH_SCHEME + jwt + AUTH_KEY_PARAM + publicKeyBase64Url;
    }

    private byte[] signRaw(String signingInput) {
        try {
            Signature sig = Signature.getInstance(SIGNATURE_ALG);
            sig.initSign(privateKey);
            sig.update(signingInput.getBytes(StandardCharsets.UTF_8));
            return sig.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new IllegalStateException("Failed to sign VAPID JWT", e);
        }
    }

    private static ECPrivateKey loadPrivateKey(String privateKeyBase64Url) {
        byte[] rawPrivate;
        try {
            rawPrivate = Base64.getUrlDecoder().decode(privateKeyBase64Url);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("VAPID private key is not valid base64url", e);
        }
        try {
            ECPrivateKeySpec spec = new ECPrivateKeySpec(new BigInteger(1, rawPrivate), EcUtils.p256Spec());
            return (ECPrivateKey) EcUtils.ecKeyFactory().generatePrivate(spec);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to load VAPID private key", e);
        }
    }

    private static byte[] toJsonBytes(Map<String, Object> map) {
        try {
            return JSON.writeValueAsBytes(map);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialise JWT JSON", e);
        }
    }

    private static String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private static byte[] derToJoseRaw(byte[] der) {
        if (der.length < DER_HEADER_BYTES || der[0] != 0x30 || der[2] != 0x02) {
            throw new IllegalStateException("Unexpected DER signature shape");
        }
        int rLen = der[3] & 0xFF;
        int sOffset = DER_HEADER_BYTES + rLen;
        if (der[sOffset] != 0x02) {
            throw new IllegalStateException("Unexpected DER signature shape");
        }
        int sLen = der[sOffset + 1] & 0xFF;
        byte[] raw = new byte[RAW_SIGNATURE_LENGTH];
        copyRightAligned(der, DER_HEADER_BYTES, rLen, raw, 0);
        copyRightAligned(der, sOffset + 2, sLen, raw, EcUtils.COORDINATE_LENGTH);
        return raw;
    }

    private static void copyRightAligned(byte[] src, int srcOffset, int srcLen, byte[] dst, int dstOffset) {
        int len = EcUtils.COORDINATE_LENGTH;
        if (srcLen > len) {
            System.arraycopy(src, srcOffset + (srcLen - len), dst, dstOffset, len);
        } else {
            System.arraycopy(src, srcOffset, dst, dstOffset + (len - srcLen), srcLen);
        }
    }

    private record CachedHeader(String header, long expiresAt) {}
}
