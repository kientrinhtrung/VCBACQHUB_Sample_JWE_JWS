package vn.com.vietcombank.acqhub.sample.refundv4.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwe;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;

/**
 * Lop JWE trong cung cua Refund v4: alg=RSA-OAEP-256, enc=A256GCM, typ=JOSE, co them
 * claim iat (unix timestamp, giay) de chong replay theo API_Refund_V4.md muc 3.2.
 */
public final class JweCryptoService {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Ma hoa JSON payload nghiep vu bang public key JWE cua ben nhan (VCB khi ma hoa
     * request, hoac doi tac khi VCB ma hoa response).
     */
    public String encrypt(String jsonPayload, RSAPublicKey recipientPublicKey, String kid) {
        try {
            return Jwts.builder()
                    .provider(BouncyCastleSupport.PROVIDER)
                    .header()
                        .type("JOSE")
                        .keyId(kid)
                        .add("iat", String.valueOf(Instant.now().getEpochSecond()))
                    .and()
                    .content(jsonPayload.getBytes(StandardCharsets.UTF_8))
                    .encryptWith(recipientPublicKey, Jwts.KEY.RSA_OAEP_256, Jwts.ENC.A256GCM)
                    .compact();
        } catch (Exception e) {
            throw new IllegalStateException("Ma hoa JWE that bai (kid=" + kid + ")", e);
        }
    }

    /**
     * Giai ma bang private key JWE cua chinh minh. Khong tu kiem tra iat/kid o day -
     * viec doi chieu do thuoc ve tang goi (RefundV4Client / MockVcbServer) vi con phu
     * thuoc chinh sach JWE_HEADER_STRICT giong ben ACQHUB that.
     */
    public DecryptedJwe decrypt(String jweCompact, RSAPrivateKey recipientPrivateKey) {
        Jwt<?, ?> jwt;
        try {
            jwt = Jwts.parser()
                    .provider(BouncyCastleSupport.PROVIDER)
                    .decryptWith(recipientPrivateKey)
                    .build()
                    .parse(jweCompact);
        } catch (MalformedJwtException e) {
            throw new SecurityException("JWE khong dung dinh dang compact serialization", e);
        } catch (Exception e) {
            throw new SecurityException("Giai ma JWE that bai", e);
        }

        if (!(jwt instanceof Jwe<?> jwe)) {
            throw new SecurityException("Token khong phai la JWE");
        }

        String kid = jwe.getHeader().getKeyId();
        Object iatVal = jwe.getHeader().get("iat");
        String iat = iatVal != null ? String.valueOf(iatVal) : null;

        String payloadJson;
        Object payload = jwe.getPayload();
        if (payload instanceof byte[] bytes) {
            payloadJson = new String(bytes, StandardCharsets.UTF_8);
        } else if (payload instanceof Claims claims) {
            try {
                payloadJson = MAPPER.writeValueAsString(claims);
            } catch (Exception e) {
                throw new SecurityException("Loi serialize Claims thanh JSON", e);
            }
        } else if (payload != null) {
            payloadJson = payload.toString();
        } else {
            payloadJson = "";
        }

        return new DecryptedJwe(payloadJson, kid, iat);
    }

    public record DecryptedJwe(String payloadJson, String kid, String iat) {
    }
}
