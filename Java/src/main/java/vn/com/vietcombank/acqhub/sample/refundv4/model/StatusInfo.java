package vn.com.vietcombank.acqhub.sample.refundv4.model;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Chi mang ma tang bao mat/transport (API_Refund_V4.md muc 5.1) - KHONG dung de doi soat
 * nghiep vu vi khong nam trong pham vi chu ky JWS.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class StatusInfo {
    public String code;
    public ErrorInfo errorInfo;
}
