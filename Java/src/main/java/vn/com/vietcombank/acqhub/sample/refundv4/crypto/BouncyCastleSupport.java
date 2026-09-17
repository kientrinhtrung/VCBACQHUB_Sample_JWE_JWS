package vn.com.vietcombank.acqhub.sample.refundv4.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

/**
 * Dang ky mot lan duy nhat va cung cap BouncyCastleProvider dung chung cho toan bo
 * module crypto (JWS, JWE, doc PEM key/cert).
 *
 * Ly do bat buoc dung provider nay thay vi de JJWT tu chon provider mac dinh cua JDK:
 * PS256 (RSASSA-PSS) chi co san native tu Java 11 tro len (SunRsaSign). Neu chi dua
 * vao JDK, project se khong chay duoc tren Java 8/9/10. Ep dung BouncyCastle cho ca
 * ky/verify JWS, ma hoa/giai ma JWE va doc khoa/cert PEM giup logic nay chay giong het
 * nhau tren moi phien ban Java (8+), khong phu thuoc thuat toan JDK co san hay khong.
 */
public final class BouncyCastleSupport {

    public static final Provider PROVIDER = resolveProvider();

    private static Provider resolveProvider() {
        Provider existing = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (existing != null) {
            return existing;
        }
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        return provider;
    }

    private BouncyCastleSupport() {
    }
}
