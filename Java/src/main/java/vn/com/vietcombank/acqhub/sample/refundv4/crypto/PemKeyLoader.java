package vn.com.vietcombank.acqhub.sample.refundv4.crypto;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Doc RSA private key (PKCS#8 PEM, "-----BEGIN PRIVATE KEY-----") va X.509 cert (PEM),
 * dung BouncyCastle lam Security Provider cho ca KeyFactory/CertificateFactory de dong
 * bo voi JwsCryptoService/JweCryptoService (xem BouncyCastleSupport).
 */
public final class PemKeyLoader {

    private PemKeyLoader() {
    }

    public static RSAPrivateKey loadPrivateKey(byte[] pkcs8Pem) {
        String pem = new String(pkcs8Pem, StandardCharsets.US_ASCII);
        String base64 = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(base64);
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA", BouncyCastleSupport.PROVIDER);
            return (RSAPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalArgumentException("PEM private key khong hop le (can dang PKCS#8)", e);
        }
    }

    public static X509Certificate loadCertificate(byte[] certPem) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleSupport.PROVIDER);
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certPem));
        } catch (CertificateException e) {
            throw new IllegalArgumentException("PEM certificate khong hop le", e);
        }
    }

    public static RSAPublicKey loadPublicKeyFromCert(byte[] certPem) {
        return (RSAPublicKey) loadCertificate(certPem).getPublicKey();
    }
}
