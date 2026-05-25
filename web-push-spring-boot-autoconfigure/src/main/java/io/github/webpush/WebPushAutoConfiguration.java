package io.github.webpush;

import io.github.webpush.crypto.ContentEncryptor;
import io.github.webpush.crypto.VapidSigner;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

import java.net.http.HttpClient;

@AutoConfiguration
@ConditionalOnClass(RestClient.class)
@ConditionalOnProperty(prefix = "webpush", name = "enabled", matchIfMissing = true)
@EnableConfigurationProperties(WebPushProperties.class)
public class WebPushAutoConfiguration {

    static final String REST_CLIENT_BEAN_NAME = "webPushRestClient";

    @Bean
    @ConditionalOnMissingBean
    VapidSigner vapidSigner(WebPushProperties props) {
        WebPushProperties.Vapid vapid = props.vapid();
        return new VapidSigner(vapid.subject(), vapid.publicKey(), vapid.privateKey());
    }

    @Bean
    @ConditionalOnMissingBean
    ContentEncryptor contentEncryptor() {
        return new ContentEncryptor();
    }

    @Bean(REST_CLIENT_BEAN_NAME)
    @ConditionalOnMissingBean(name = REST_CLIENT_BEAN_NAME)
    RestClient webPushRestClient(WebPushProperties props) {
        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(props.connectTimeout())
                .build();
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(httpClient);
        factory.setReadTimeout(props.readTimeout());
        return RestClient.builder().requestFactory(factory).build();
    }

    @Bean
    @ConditionalOnMissingBean
    WebPushService webPushService(VapidSigner signer, ContentEncryptor encryptor,
                                  WebPushProperties props,
                                  @Qualifier(REST_CLIENT_BEAN_NAME) RestClient webPushRestClient) {
        return new WebPushServiceImpl(signer, encryptor, props, webPushRestClient);
    }
}
