package io.github.classicpintus.webpush;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;
import java.util.Objects;

public record PushSubscription(
        String endpoint,
        String p256dh,
        String auth
) {
    public PushSubscription {
        Objects.requireNonNull(endpoint, "endpoint must not be null");
        Objects.requireNonNull(p256dh, "p256dh must not be null");
        Objects.requireNonNull(auth, "auth must not be null");
        validateEndpoint(endpoint);
        decode(p256dh, "p256dh");
        decode(auth, "auth");
    }

    public byte[] p256dhBytes() {
        return Base64.getUrlDecoder().decode(p256dh);
    }

    public byte[] authBytes() {
        return Base64.getUrlDecoder().decode(auth);
    }

    private static void validateEndpoint(String endpoint) {
        try {
            URI uri = new URI(endpoint);
            if (uri.getScheme() == null || uri.getAuthority() == null) {
                throw new IllegalArgumentException("endpoint must be an absolute URL: " + endpoint);
            }
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("endpoint is not a valid URL: " + endpoint, e);
        }
    }

    private static void decode(String value, String field) {
        try {
            Base64.getUrlDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(field + " is not valid base64url", e);
        }
    }
}
