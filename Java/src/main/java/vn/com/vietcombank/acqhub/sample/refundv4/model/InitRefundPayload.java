package vn.com.vietcombank.acqhub.sample.refundv4.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.math.BigDecimal;

/**
 * Payload nghiep vu sau khi giai ma JWE (API_Refund_V4.md muc 4.2).
 * Cac truong bat buoc: paymentRef, refundRequestId, amount, payType, mid, auditData.channel/channelUser.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class InitRefundPayload {
    public String requestId;
    public String mid;
    public String tid;
    public String paymentRef;
    public String partnerRefId;
    public String refundRequestId;
    public BigDecimal amount;
    public String payType;
    public String paymentInfo;
    public String billNumber;
    public AuditData auditData;
}
