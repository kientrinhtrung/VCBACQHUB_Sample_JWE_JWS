package vn.com.vietcombank.acqhub.sample.refundv4.mock;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import vn.com.vietcombank.acqhub.sample.refundv4.config.AppConfig;
import vn.com.vietcombank.acqhub.sample.refundv4.crypto.JweCryptoService;
import vn.com.vietcombank.acqhub.sample.refundv4.crypto.JwsCryptoService;
import vn.com.vietcombank.acqhub.sample.refundv4.crypto.PemKeyLoader;
import vn.com.vietcombank.acqhub.sample.refundv4.model.ErrorInfo;
import vn.com.vietcombank.acqhub.sample.refundv4.model.InitRefundPayload;
import vn.com.vietcombank.acqhub.sample.refundv4.model.InitRefundResultPayload;
import vn.com.vietcombank.acqhub.sample.refundv4.model.MessageHeader;
import vn.com.vietcombank.acqhub.sample.refundv4.model.RefundRequestEnvelope;
import vn.com.vietcombank.acqhub.sample.refundv4.model.RefundResponseEnvelope;
import vn.com.vietcombank.acqhub.sample.refundv4.model.StatusInfo;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * Gia lap phia VCB CHI DE CHAY THU luong JWE/JWS cua RefundV4Client tren may local,
 * bam sat dung 12 buoc xu ly va bang ma loi trong ZDocs/API_Refund_V4.md.
 *
 * KHONG dung mock nay lam tham chieu bao mat: no bo qua hoan toan buoc kiem tra
 * chain + OCSP chung thu doi tac (muc 3.4 tai lieu), vi day chi la vi du dan giay
 * dinh dang JOSE, khong phai ban sao logic PartnerCertValidator that.
 */
public final class MockVcbServer {

    public static void main(String[] args) throws IOException, InterruptedException {
        AppConfig config = new AppConfig();
        ObjectMapper mapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

        JwsCryptoService jwsCrypto = new JwsCryptoService();
        JweCryptoService jweCrypto = new JweCryptoService();

        RSAPrivateKey vcbJwsPrivateKey = PemKeyLoader.loadPrivateKey(config.readFile("mock.vcb.jws.privateKeyPath"));
        String vcbJwsKid = config.get("mock.vcb.jws.kid");

        RSAPrivateKey vcbJwePrivateKey = PemKeyLoader.loadPrivateKey(config.readFile("mock.vcb.jwe.privateKeyPath"));

        RSAPublicKey merchantJwsPublicKey = PemKeyLoader.loadPublicKeyFromCert(config.readFile("mock.merchant.jws.certPath"));
        String merchantJwsExpectedKid = config.get("mock.merchant.jws.expectedKid");

        RSAPublicKey merchantJwePublicKey = PemKeyLoader.loadPublicKeyFromCert(config.readFile("mock.merchant.jwe.certPath"));
        String merchantJweKid = config.get("mock.merchant.jwe.kid");

        int port = config.getInt("mock.server.port");
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        server.createContext("/oauth/token", exchange -> handleOAuthToken(exchange, mapper));

        server.createContext("/api/acqhub/utilities/partner/v4/", exchange -> handleRefund(
                exchange, mapper, jwsCrypto, jweCrypto,
                vcbJwsPrivateKey, vcbJwsKid, vcbJwePrivateKey,
                merchantJwsPublicKey, merchantJwsExpectedKid, merchantJwePublicKey, merchantJweKid));

        server.setExecutor(null);
        server.start();
        System.out.println("MockVcbServer dang chay tai http://localhost:" + port);
        System.out.println("Dung bang Ctrl+C (hoac kill process).");

        Runtime.getRuntime().addShutdownHook(new Thread(() -> server.stop(0)));
        Thread.currentThread().join();
    }

    private static void handleOAuthToken(HttpExchange exchange, ObjectMapper mapper) throws IOException {
        String body = "{\"access_token\":\"mock-access-token\",\"token_type\":\"Bearer\",\"expires_in\":3600}";
        writeJson(exchange, 200, body);
    }

    private static void handleRefund(
            HttpExchange exchange,
            ObjectMapper mapper,
            JwsCryptoService jwsCrypto,
            JweCryptoService jweCrypto,
            RSAPrivateKey vcbJwsPrivateKey,
            String vcbJwsKid,
            RSAPrivateKey vcbJwePrivateKey,
            RSAPublicKey merchantJwsPublicKey,
            String merchantJwsExpectedKid,
            RSAPublicKey merchantJwePublicKey,
            String merchantJweKid
    ) throws IOException {
        String requestId = UUID.randomUUID().toString();
        try {
            String rawBody = readBody(exchange);
            RefundRequestEnvelope requestEnvelope = mapper.readValue(rawBody, RefundRequestEnvelope.class);

            if (requestEnvelope.encryptedPayload == null || requestEnvelope.partnerCode == null || requestEnvelope.mid == null) {
                sendErrorEnvelope(exchange, mapper, requestEnvelope, "99", "Bad request");
                return;
            }

            // Buoc 5 (tai lieu muc 7): verify JWS bang MERCHANT_JWS_CERT + doi chieu kid.
            // (Buoc 6 - kiem tra chain/OCSP chung thu - KHONG duoc mo phong o day, xem javadoc lop nay.)
            String innerJwe;
            try {
                innerJwe = jwsCrypto.verify(requestEnvelope.encryptedPayload, merchantJwsPublicKey, merchantJwsExpectedKid);
            } catch (SecurityException e) {
                sendErrorEnvelope(exchange, mapper, requestEnvelope, "98", "Invalid Signature");
                return;
            }

            // Buoc 7: giai ma JWE bang VCB_JWE_PRIVATE_KEY.
            InitRefundPayload payload;
            try {
                JweCryptoService.DecryptedJwe decrypted = jweCrypto.decrypt(innerJwe, vcbJwePrivateKey);
                payload = mapper.readValue(decrypted.payloadJson(), InitRefundPayload.class);
            } catch (RuntimeException e) {
                sendErrorEnvelope(exchange, mapper, requestEnvelope, "97", "Invalid Encryption");
                return;
            }

            // Buoc 8 (chi v4): refundRequestId + auditData.channel/channelUser bat buoc.
            if (payload.refundRequestId == null || payload.refundRequestId.isBlank()
                    || payload.auditData == null
                    || payload.auditData.channel == null || payload.auditData.channel.isBlank()
                    || payload.auditData.channelUser == null || payload.auditData.channelUser.isBlank()) {
                sendBusinessResult(exchange, mapper, requestEnvelope, jwsCrypto, jweCrypto,
                        vcbJwsPrivateKey, vcbJwsKid, merchantJwePublicKey, merchantJweKid,
                        "03", "INPUT_CHECK_FAIL", payload);
                return;
            }

            // Mock khong noi voi core that: luon tra "00 Succeed" giong tai lieu muc 5.2.
            sendBusinessResult(exchange, mapper, requestEnvelope, jwsCrypto, jweCrypto,
                    vcbJwsPrivateKey, vcbJwsKid, merchantJwePublicKey, merchantJweKid,
                    "00", "Succeed", payload);

        } catch (Exception e) {
            System.err.println("[" + requestId + "] MockVcbServer loi khong xac dinh: " + e);
            writeJson(exchange, 200, "{\"status\":{\"code\":\"9999\",\"errorInfo\":{\"message\":\"System temporary unavailable\"}},\"encryptedPayload\":\"\"}");
        }
    }

    private static void sendBusinessResult(
            HttpExchange exchange,
            ObjectMapper mapper,
            RefundRequestEnvelope requestEnvelope,
            JwsCryptoService jwsCrypto,
            JweCryptoService jweCrypto,
            RSAPrivateKey vcbJwsPrivateKey,
            String vcbJwsKid,
            RSAPublicKey merchantJwePublicKey,
            String merchantJweKid,
            String code,
            String message,
            InitRefundPayload payload
    ) throws IOException {
        InitRefundResultPayload result = new InitRefundResultPayload();
        result.code = code;
        result.message = message;
        result.requestId = payload.requestId;
        result.operation = "InitRefund";
        result.payChannel = "VIETCOMBANK";
        result.payTypeHandle = "VCB";
        result.remark = payload.paymentInfo;
        result.amount = payload.amount;

        String resultJson = mapper.writeValueAsString(result);
        String jwe = jweCrypto.encrypt(resultJson, merchantJwePublicKey, merchantJweKid);
        String jws = jwsCrypto.sign(jwe, vcbJwsPrivateKey, vcbJwsKid);

        RefundResponseEnvelope responseEnvelope = new RefundResponseEnvelope();
        responseEnvelope.header = new MessageHeader(
                requestEnvelope.header != null ? requestEnvelope.header.id : UUID.randomUUID().toString(),
                "VIETCOMBANK", "PARTNER",
                requestEnvelope.header != null ? requestEnvelope.header.id : null);
        responseEnvelope.status = new StatusInfo();
        responseEnvelope.status.code = "00";
        responseEnvelope.status.errorInfo = errorInfo("00", "Succeed");
        responseEnvelope.encryptedPayload = jws;

        writeJson(exchange, 200, mapper.writeValueAsString(responseEnvelope));
    }

    private static void sendErrorEnvelope(
            HttpExchange exchange, ObjectMapper mapper, RefundRequestEnvelope requestEnvelope,
            String statusCode, String statusMessage
    ) throws IOException {
        RefundResponseEnvelope responseEnvelope = new RefundResponseEnvelope();
        responseEnvelope.header = new MessageHeader(
                requestEnvelope != null && requestEnvelope.header != null ? requestEnvelope.header.id : UUID.randomUUID().toString(),
                "VIETCOMBANK", "PARTNER",
                requestEnvelope != null && requestEnvelope.header != null ? requestEnvelope.header.id : null);
        responseEnvelope.status = new StatusInfo();
        responseEnvelope.status.code = statusCode;
        responseEnvelope.status.errorInfo = errorInfo(statusCode, statusMessage);
        responseEnvelope.encryptedPayload = "";
        writeJson(exchange, 200, mapper.writeValueAsString(responseEnvelope));
    }

    private static ErrorInfo errorInfo(String id, String message) {
        ErrorInfo info = new ErrorInfo();
        info.id = id;
        info.message = message;
        return info;
    }

    private static String readBody(HttpExchange exchange) throws IOException {
        try (InputStream is = exchange.getRequestBody()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static void writeJson(HttpExchange exchange, int statusCode, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private MockVcbServer() {
    }
}
