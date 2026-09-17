package vn.com.vietcombank.acqhub.sample.refundv4;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import vn.com.vietcombank.acqhub.sample.refundv4.config.AppConfig;
import vn.com.vietcombank.acqhub.sample.refundv4.crypto.JweCryptoService;
import vn.com.vietcombank.acqhub.sample.refundv4.crypto.JwsCryptoService;
import vn.com.vietcombank.acqhub.sample.refundv4.crypto.PemKeyLoader;
import vn.com.vietcombank.acqhub.sample.refundv4.model.AuditData;
import vn.com.vietcombank.acqhub.sample.refundv4.model.InitRefundPayload;
import vn.com.vietcombank.acqhub.sample.refundv4.model.InitRefundResultPayload;
import vn.com.vietcombank.acqhub.sample.refundv4.model.MessageHeader;
import vn.com.vietcombank.acqhub.sample.refundv4.model.RefundRequestEnvelope;
import vn.com.vietcombank.acqhub.sample.refundv4.model.RefundResponseEnvelope;
import vn.com.vietcombank.acqhub.sample.refundv4.oauth.OAuthTokenClient;

import java.math.BigDecimal;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

/**
 * Sample client dong vai tro DOI TAC, goi API Init Refund V4 cua VCB:
 *   plaintext -> JWE (ma hoa bang cert JWE cua VCB) -> JWS (ky bang khoa JWS cua doi tac)
 * Sau do doc response:
 *   verify JWS (bang cert JWS cua VCB) -> giai ma JWE (bang khoa JWE cua doi tac) -> ket qua nghiep vu.
 *
 * Mac dinh cau hinh (application.properties) tro vao MockVcbServer chay tren localhost.
 * De goi VCB that: doi vcb.baseUrl + vcb.oauth.* + 4 khoa merchant/vcb.* sang gia tri that,
 * va KHONG duoc dua private key that vao thu muc mock-only.
 */
public final class RefundV4Client {

    public static void main(String[] args) throws Exception {
        AppConfig config = new AppConfig();
        ObjectMapper mapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

        JwsCryptoService jwsCrypto = new JwsCryptoService();
        JweCryptoService jweCrypto = new JweCryptoService();

        RSAPrivateKey merchantJwsPrivateKey = PemKeyLoader.loadPrivateKey(config.readFile("merchant.jws.privateKeyPath"));
        String merchantJwsKid = config.get("merchant.jws.kid");

        RSAPublicKey vcbJwePublicKey = PemKeyLoader.loadPublicKeyFromCert(config.readFile("vcb.jwe.certPath"));
        String vcbJweKid = config.get("vcb.jwe.kid");

        RSAPublicKey vcbJwsPublicKey = PemKeyLoader.loadPublicKeyFromCert(config.readFile("vcb.jws.certPath"));
        String vcbJwsExpectedKid = config.get("vcb.jws.expectedKid");

        RSAPrivateKey merchantJwePrivateKey = PemKeyLoader.loadPrivateKey(config.readFile("merchant.jwe.privateKeyPath"));

        String partnerCode = config.get("partner.code");
        String mid = config.get("mid");
        String tid = config.get("tid", null);

        String requestId = UUID.randomUUID().toString();

        // ----- 1. Dung payload nghiep vu mau (thay bang du lieu that khi tich hop) -----
        InitRefundPayload payload = new InitRefundPayload();
        payload.requestId = requestId;
        payload.mid = mid;
        payload.tid = tid;
        payload.paymentRef = "SAMPLE-PAYMENT-REF-0001";
        payload.refundRequestId = "RF" + System.currentTimeMillis();
        payload.amount = new BigDecimal("100000");
        payload.payType = "RF";
        payload.paymentInfo = "Hoan tien don hang sample";
        payload.billNumber = "0001";
        AuditData audit = new AuditData();
        audit.channel = "SAMPLE_APP";
        audit.channelIp = "127.0.0.1";
        audit.channelUser = "sample-user";
        payload.auditData = audit;

        String payloadJson = mapper.writeValueAsString(payload);
        System.out.println("[" + requestId + "] Payload nghiep vu (truoc ma hoa): " + payloadJson);

        // ----- 2. JWE (lop trong): ma hoa bang cert cong khai JWE cua VCB -----
        String jweCompact = jweCrypto.encrypt(payloadJson, vcbJwePublicKey, vcbJweKid);
        System.out.println("[" + requestId + "] JWE (compact): " + jweCompact);

        // ----- 3. JWS (lop ngoai): ky chuoi JWE o tren bang khoa private JWS cua doi tac -----
        String jwsCompact = jwsCrypto.sign(jweCompact, merchantJwsPrivateKey, merchantJwsKid);
        System.out.println("[" + requestId + "] JWS (compact, se gui trong encryptedPayload): " + jwsCompact);

        // ----- 4. Goi API -----
        RefundRequestEnvelope requestEnvelope = new RefundRequestEnvelope();
        requestEnvelope.header = new MessageHeader(requestId, "PARTNER", "VIETCOMBANK", UUID.randomUUID().toString());
        requestEnvelope.mid = mid;
        requestEnvelope.tid = tid;
        requestEnvelope.partnerCode = partnerCode;
        requestEnvelope.encryptedPayload = jwsCompact;

        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();

        OAuthTokenClient oauthClient = new OAuthTokenClient(
                httpClient,
                config.get("vcb.oauth.tokenUrl"),
                config.get("vcb.oauth.clientId"),
                config.get("vcb.oauth.clientSecret"));
        String bearerToken = oauthClient.fetchAccessToken();

        String url = String.format(config.get("vcb.refundV4.urlTemplate"), partnerCode);
        String requestBody = mapper.writeValueAsString(requestEnvelope);
        System.out.println("[" + requestId + "] POST " + url);

        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/json")
                .header("Authorization", bearerToken)
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        HttpResponse<String> httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        System.out.println("[" + requestId + "] HTTP status: " + httpResponse.statusCode());
        System.out.println("[" + requestId + "] Response body: " + httpResponse.body());

        RefundResponseEnvelope responseEnvelope = mapper.readValue(httpResponse.body(), RefundResponseEnvelope.class);

        // ----- 5. Doc ket qua theo dung quy tac muc 5.3 cua tai lieu: -----
        //     encryptedPayload khac rong -> giai ma lay code/message BEN TRONG lam ket qua chinh thuc.
        //     encryptedPayload rong       -> loi tang bao mat/transport, doc status ngoai de chan doan.
        if (responseEnvelope.encryptedPayload != null && !responseEnvelope.encryptedPayload.isEmpty()) {
            String innerJwe = jwsCrypto.verify(responseEnvelope.encryptedPayload, vcbJwsPublicKey, vcbJwsExpectedKid);
            JweCryptoService.DecryptedJwe decrypted = jweCrypto.decrypt(innerJwe, merchantJwePrivateKey);
            InitRefundResultPayload result = mapper.readValue(decrypted.payloadJson(), InitRefundResultPayload.class);

            System.out.println("==== KET QUA NGHIEP VU (da xac thuc chu ky) ====");
            System.out.println("code    = " + result.code);
            System.out.println("message = " + result.message);
            System.out.println("amount  = " + result.amount);
            System.out.println("payChannel = " + result.payChannel);
        } else {
            System.out.println("==== LOI TANG BAO MAT / TRANSPORT (chua toi buoc xu ly nghiep vu) ====");
            System.out.println("status.code = " + (responseEnvelope.status != null ? responseEnvelope.status.code : null));
            if (responseEnvelope.status != null && responseEnvelope.status.errorInfo != null) {
                System.out.println("message     = " + responseEnvelope.status.errorInfo.message);
            }
        }
    }

    private RefundV4Client() {
    }
}
