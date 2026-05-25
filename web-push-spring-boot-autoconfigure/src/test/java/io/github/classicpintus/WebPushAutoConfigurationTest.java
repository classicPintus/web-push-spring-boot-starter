package io.github.classicpintus;

import io.github.classicpintus.crypto.ContentEncryptor;
import io.github.classicpintus.crypto.VapidSigner;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import static org.assertj.core.api.Assertions.assertThat;

class WebPushAutoConfigurationTest {

    static String testPubKey;
    static String testPrivKey;

    @BeforeAll
    static void generateKeys() throws Exception {
        KeyPair kp = TestKeyHelper.generateP256KeyPair();
        testPubKey = TestKeyHelper.encodePublicKey((ECPublicKey) kp.getPublic());
        testPrivKey = TestKeyHelper.encodePrivateKey((ECPrivateKey) kp.getPrivate());
    }

    private ApplicationContextRunner runner() {
        return new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(WebPushAutoConfiguration.class))
                .withPropertyValues(
                        "webpush.vapid.subject=mailto:test@test.com",
                        "webpush.vapid.public-key=" + testPubKey,
                        "webpush.vapid.private-key=" + testPrivKey
                );
    }

    @Test
    void webPushService_isAutoConfigured() {
        runner().run(ctx -> assertThat(ctx).hasSingleBean(WebPushService.class));
    }

    @Test
    void vapidSigner_isAutoConfigured() {
        runner().run(ctx -> assertThat(ctx).hasSingleBean(VapidSigner.class));
    }

    @Test
    void contentEncryptor_isAutoConfigured() {
        runner().run(ctx -> assertThat(ctx).hasSingleBean(ContentEncryptor.class));
    }

    @Test
    void webPushRestClient_isAutoConfigured() {
        runner().run(ctx -> assertThat(ctx).hasBean(WebPushAutoConfiguration.REST_CLIENT_BEAN_NAME));
    }

    @Test
    void webPushRestClient_backsOff_whenNamedBeanProvided() {
        runner()
                .withUserConfiguration(CustomNamedRestClientConfig.class)
                .run(ctx -> assertThat(ctx.getBean(WebPushAutoConfiguration.REST_CLIENT_BEAN_NAME, RestClient.class))
                        .isSameAs(CustomNamedRestClientConfig.INSTANCE));
    }

    @Test
    void webPushRestClient_isCreated_whenUnrelatedRestClientPresent() {
        runner()
                .withUserConfiguration(UnrelatedRestClientConfig.class)
                .run(ctx -> {
                    assertThat(ctx).getBeans(RestClient.class).hasSize(2);
                    assertThat(ctx.containsBean(WebPushAutoConfiguration.REST_CLIENT_BEAN_NAME)).isTrue();
                });
    }

    @Test
    void webPushService_notCreated_whenCustomBeanPresent() {
        runner()
                .withUserConfiguration(CustomWebPushConfig.class)
                .run(ctx -> {
                    assertThat(ctx).hasSingleBean(WebPushService.class);
                    assertThat(ctx.getBean(WebPushService.class)).isInstanceOf(CustomWebPushConfig.NoOpService.class);
                });
    }

    @Test
    void disabled_byEnabledFalse() {
        runner()
                .withPropertyValues("webpush.enabled=false")
                .run(ctx -> assertThat(ctx).doesNotHaveBean(WebPushService.class));
    }

    @Test
    void context_failsWithMissingVapidSubject() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(WebPushAutoConfiguration.class))
                .withPropertyValues(
                        "webpush.vapid.public-key=" + testPubKey,
                        "webpush.vapid.private-key=" + testPrivKey
                )
                .run(ctx -> {
                    assertThat(ctx).hasFailed();
                    assertThat(ctx.getStartupFailure()).hasStackTraceContaining("vapid.subject");
                });
    }

    @Test
    void context_failsWithInvalidSubjectScheme() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(WebPushAutoConfiguration.class))
                .withPropertyValues(
                        "webpush.vapid.subject=ftp://nope",
                        "webpush.vapid.public-key=" + testPubKey,
                        "webpush.vapid.private-key=" + testPrivKey
                )
                .run(ctx -> assertThat(ctx).hasFailed());
    }

    @Configuration
    static class CustomNamedRestClientConfig {
        static final RestClient INSTANCE = RestClient.create();

        @Bean(WebPushAutoConfiguration.REST_CLIENT_BEAN_NAME)
        RestClient webPushRestClient() { return INSTANCE; }
    }

    @Configuration
    static class UnrelatedRestClientConfig {
        @Bean
        RestClient myOwnRestClient() { return RestClient.create(); }
    }

    @Configuration
    static class CustomWebPushConfig {
        @Bean
        WebPushService webPushService() { return new NoOpService(); }

        static class NoOpService implements WebPushService {
            @Override public SendResult send(PushSubscription s, String p) {
                return SendResult.ok(s, null, 1);
            }
        }
    }
}
