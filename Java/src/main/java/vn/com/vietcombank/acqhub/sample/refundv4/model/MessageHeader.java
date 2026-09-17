package vn.com.vietcombank.acqhub.sample.refundv4.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class MessageHeader {
    public String id;
    public String recipient;
    public String sender;
    public Instant ts;
    public String exchangeId;

    public MessageHeader() {
    }

    public MessageHeader(String id, String sender, String recipient, String exchangeId) {
        this.id = id;
        this.sender = sender;
        this.recipient = recipient;
        this.exchangeId = exchangeId;
        this.ts = Instant.now();
    }
}
