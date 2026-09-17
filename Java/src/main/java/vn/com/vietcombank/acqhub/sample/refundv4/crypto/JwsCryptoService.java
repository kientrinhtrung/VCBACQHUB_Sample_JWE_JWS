package vn.com.vietcombank.acqhub.sample.refundv4.crypto;

import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Lop JWS ngoai cung cua Refund v4: alg=PS256, typ=JOSE, cty=JWE.
 * Payload cua JWS o day KHONG phai JSON nghiep vu, ma la chuoi JWE compact da ma hoa
 * (dung dinh dang API_Refund_V4.md muc 3.1/3.2: "JWS la lop ngoai, JWE la lop trong").
 */
public final class JwsCryptoService {

    /**
     * Ky mot chuoi JWE compact bang private key JWS cua ben goi (doi tac khi goi request,
     * hoac VCB khi tra response).
     */
    public String sign(String jweCompactPayload, RSAPrivateKey signingKey, String kid) {
        try {
            return Jwts.builder()
                    .provider(BouncyCastleSupport.PROVIDER)
                    .header()
                        .type("JOSE")
                        .contentType("JWE")
                        .keyId(kid)
                    .and()
                    .content(jweCompactPayload.getBytes(StandardCharsets.UTF_8))
                    .signWith(signingKey, Jwts.SIG.PS256)
                    .compact();
        } catch (Exception e) {
            throw new IllegalStateException("Ky JWS that bai (kid=" + kid + ")", e);
        }
    }

    /**
     * Verify chu ky JWS bang public key (lay tu cert cua ben ky) va doi chieu kid.
     * Tra ve payload ben trong (chuoi JWE compact) khi hop le.
     */
    public String verify(String jwsCompact, RSAPublicKey verifyingKey, String expectedKid) {
        Jws<byte[]> jws;
        try {
            jws = Jwts.parser()
                    .provider(BouncyCastleSupport.PROVIDER)
                    .verifyWith(verifyingKey)
                    .build()
                    .parseSignedContent(jwsCompact);
        } catch (MalformedJwtException e) {
            throw new SecurityException("JWS khong dung dinh dang compact serialization", e);
        } catch (SignatureException e) {
            throw new SecurityException("Chu ky JWS khong hop le", e);
        } catch (Exception e) {
            throw new SecurityException("Verify JWS that bai", e);
        }

        String actualKid = jws.getHeader().getKeyId();
        if (expectedKid != null && !expectedKid.equals(actualKid)) {
            throw new SecurityException("kid khong khop: expected=" + expectedKid + ", actual=" + actualKid);
        }

        return new String(jws.getPayload(), StandardCharsets.UTF_8);
    }
}
