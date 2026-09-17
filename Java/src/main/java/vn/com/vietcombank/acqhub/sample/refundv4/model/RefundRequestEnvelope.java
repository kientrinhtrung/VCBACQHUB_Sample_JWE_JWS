package vn.com.vietcombank.acqhub.sample.refundv4.model;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Body lop ngoai (plaintext) cua request - API_Refund_V4.md muc 4.1.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RefundRequestEnvelope {
    public MessageHeader header;
    public String mid;
    public String tid;
    public String partnerCode;
    public String encryptedPayload;
}
