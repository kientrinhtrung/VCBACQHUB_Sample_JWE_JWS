package vn.com.vietcombank.acqhub.sample.refundv4.model;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Body lop ngoai (plaintext, khong duoc ky) cua response - API_Refund_V4.md muc 5.1.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RefundResponseEnvelope {
    public MessageHeader header;
    public StatusInfo status;
    public String encryptedPayload;
}
