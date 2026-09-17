package vn.com.vietcombank.acqhub.sample.refundv4.crypto;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

public class CryptoServicesTest {

    private static RSAPublicKey jwePublicKey;
    private static RSAPrivateKey jwePrivateKey;
    private static RSAPublicKey jwsPublicKey;
    private static RSAPrivateKey jwsPrivateKey;

    private final JweCryptoService jweCrypto = new JweCryptoService();
    private final JwsCryptoService jwsCrypto = new JwsCryptoService();

    @BeforeAll
    static void setUpKeys() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);

        KeyPair jweKp = kpg.generateKeyPair();
        jwePublicKey = (RSAPublicKey) jweKp.getPublic();
        jwePrivateKey = (RSAPrivateKey) jweKp.getPrivate();

        KeyPair jwsKp = kpg.generateKeyPair();
        jwsPublicKey = (RSAPublicKey) jwsKp.getPublic();
        jwsPrivateKey = (RSAPrivateKey) jwsKp.getPrivate();
    }

    @Test
    void testJweEncryptAndDecrypt() {
        String originalJson = "{\"requestId\":\"req-123\",\"amount\":50000}";
        String kid = "VCB_JWE_KID_TEST";

        long beforeSec = Instant.now().getEpochSecond() - 1;
        String jweCompact = jweCrypto.encrypt(originalJson, jwePublicKey, kid);
        assertNotNull(jweCompact);
        assertEquals(5, jweCompact.split("\\.").length, "JWE compact serialization phai gom 5 phan");

        JweCryptoService.DecryptedJwe decrypted = jweCrypto.decrypt(jweCompact, jwePrivateKey);
        assertEquals(originalJson, decrypted.payloadJson());
        assertEquals(kid, decrypted.kid());
        assertNotNull(decrypted.iat());

        long iatSec = Long.parseLong(decrypted.iat());
        assertTrue(iatSec >= beforeSec && iatSec <= Instant.now().getEpochSecond() + 2);
    }

    @Test
    void testJwsSignAndVerify() {
        String payload = "sample.jwe.compact.payload";
        String kid = "MERCHANT_JWS_KID_TEST";

        String jwsCompact = jwsCrypto.sign(payload, jwsPrivateKey, kid);
        assertNotNull(jwsCompact);
        assertEquals(3, jwsCompact.split("\\.").length, "JWS compact serialization phai gom 3 phan");

        // Verify thanh cong voi dung expectedKid
        String verifiedPayload = jwsCrypto.verify(jwsCompact, jwsPublicKey, kid);
        assertEquals(payload, verifiedPayload);

        // Verify thanh cong voi expectedKid == null
        String verifiedWithoutKidCheck = jwsCrypto.verify(jwsCompact, jwsPublicKey, null);
        assertEquals(payload, verifiedWithoutKidCheck);

        // Verify that bai neu sai expectedKid
        assertThrows(SecurityException.class, () -> {
            jwsCrypto.verify(jwsCompact, jwsPublicKey, "WRONG_KID");
        });
    }

    @Test
    void testNestedJweInsideJwsRoundTrip() {
        String originalBusinessPayload = "{\"paymentRef\":\"REF001\",\"status\":\"SUCCESS\"}";
        String jweKid = "VCB_JWE_01";
        String jwsKid = "MERCHANT_JWS_01";

        // Step 1: Encrypt JWE
        String jweCompact = jweCrypto.encrypt(originalBusinessPayload, jwePublicKey, jweKid);

        // Step 2: Sign JWS wrapping JWE
        String jwsCompact = jwsCrypto.sign(jweCompact, jwsPrivateKey, jwsKid);

        // Step 3: Verify JWS
        String extractedJwe = jwsCrypto.verify(jwsCompact, jwsPublicKey, jwsKid);
        assertEquals(jweCompact, extractedJwe);

        // Step 4: Decrypt JWE
        JweCryptoService.DecryptedJwe result = jweCrypto.decrypt(extractedJwe, jwePrivateKey);
        assertEquals(originalBusinessPayload, result.payloadJson());
        assertEquals(jweKid, result.kid());
    }
}
