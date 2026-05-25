package io.github.classicpintus;

import io.github.classicpintus.crypto.ContentEncryptor;
import io.github.classicpintus.crypto.VapidSigner;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;

@Disabled
class WebPushServiceFcmIntegrationTest {

    private static final String VAPID_PUBLIC_KEY =
            "BAbqEWzE2NILzLC6qyjAak8R72eaLaqx9NcBnECtms38X-JEi5ghROaF9Tacq0Cmir1GAqc7FJ7HDt25ms8Q2Yg";
    private static final String VAPID_PRIVATE_KEY =
            "3ozVwA5qPndx6nj-E6U-OsoNp-pKdstsH9SB_E0ljXo";
    private static final String VAPID_SUBJECT = "mailto:info@classicviruslist.com";

    private static final String ENDPOINT =
            "https://fcm.googleapis.com/fcm/send/dw7soPDt060:APA91bGixLrsGRFNPLv0afaxKcPwBbXgI9BW1x9LxP_GVBDEE7l_HdSQWFbGwmCJD_rXiBUHJEAyQzMR0B-kGMH964pr2QxlJ3vsnb5RexHN7KVO2VKTeyRjW4qDV_sh2yu1gcC0T9vu";
    private static final String P256DH =
            "BEMuLCAfECSoHZC3-zAKNGggsWBe7j7oUH1ya4k-5ozAReOxU3P6K40BfV7caqhtYe6pgEdGD2jQmR8luCXZpeI";
    private static final String AUTH = "I_f3K2l7-cRF7ylS9O7uCw";

    @Test
    void sendsRealNotificationToFcm() {
        WebPushProperties props = new WebPushProperties(
                new WebPushProperties.Vapid(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY),
                null, null, null, null);
        VapidSigner signer = new VapidSigner(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
        WebPushServiceImpl service = new WebPushServiceImpl(
                signer, new ContentEncryptor(), props, RestClient.builder().build());

        PushSubscription subscription = new PushSubscription(ENDPOINT, P256DH, AUTH);

        SendResult result = service.send(subscription, "{}");

        System.out.println("FCM response status: " + result.statusCode());
        if (result.error() != null) {
            System.out.println("FCM error: " + result.error().getMessage());
        }

        assertThat(result.success())
                .as("FCM send should succeed; got status=%s error=%s",
                        result.statusCode(), result.error())
                .isTrue();
    }
}
