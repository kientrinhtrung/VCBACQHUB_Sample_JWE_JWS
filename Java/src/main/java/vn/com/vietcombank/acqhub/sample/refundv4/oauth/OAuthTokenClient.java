package vn.com.vietcombank.acqhub.sample.refundv4.oauth;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Lay bearer token bang grant_type=client_credentials, tuong tu Program.LoginJWT() ben
 * sample C# (VCBACQHUB_Sample_JWE_JWS).
 */
public class OAuthTokenClient {

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final String tokenUrl;
    private final String clientId;
    private final String clientSecret;

    public OAuthTokenClient(HttpClient httpClient, String tokenUrl, String clientId, String clientSecret) {
        this.httpClient = httpClient;
        this.tokenUrl = tokenUrl;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public String fetchAccessToken() throws IOException, InterruptedException {
        String form = "grant_type=client_credentials"
                + "&client_id=" + urlEncode(clientId)
                + "&client_secret=" + urlEncode(clientSecret);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(tokenUrl))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form, StandardCharsets.UTF_8))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("Lay token that bai, HTTP " + response.statusCode() + ": " + response.body());
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> body = objectMapper.readValue(response.body(), Map.class);
        Object tokenType = body.getOrDefault("token_type", "Bearer");
        Object accessToken = body.get("access_token");
        if (accessToken == null) {
            throw new IOException("Response OAuth khong co access_token: " + response.body());
        }
        return tokenType + " " + accessToken;
    }

    private static String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
