package vn.com.vietcombank.acqhub.sample.refundv4.model;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuditData {
    public String channel;
    public String channelIp;
    public String channelUser;
    public String channelUserBranch;
    public String channelTime;
}
