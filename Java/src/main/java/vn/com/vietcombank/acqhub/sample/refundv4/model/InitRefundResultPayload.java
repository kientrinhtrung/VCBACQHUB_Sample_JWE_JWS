package vn.com.vietcombank.acqhub.sample.refundv4.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.math.BigDecimal;

/**
 * Payload nghiep vu sau khi giai ma JWE cua response - ket qua chinh thuc dung de doi
 * soat, theo API_Refund_V4.md muc 5.2.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class InitRefundResultPayload {
    public String code;
    public String message;
    public String requestId;
    public String serverTime;
    public String operation;
    public String payChannel;
    public String payTypeHandle;
    public String remark;
    public BigDecimal amount;
}
