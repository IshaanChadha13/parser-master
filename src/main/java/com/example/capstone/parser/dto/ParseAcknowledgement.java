package com.example.capstone.parser.dto;

import com.example.capstone.parser.model.Acknowledgement;
import com.example.capstone.parser.model.AcknowledgementEvent;

import java.util.UUID;

public class ParseAcknowledgement implements Acknowledgement<AcknowledgementEvent> {

    private String acknowledgementId;
    private AcknowledgementEvent payload;

    public ParseAcknowledgement() {}
    public ParseAcknowledgement(String acknowledgementId, AcknowledgementEvent payload) {
        this.acknowledgementId = (acknowledgementId == null || acknowledgementId.isEmpty()) ? UUID.randomUUID().toString() : acknowledgementId;
        this.payload = payload;
    }
    public void setAcknowledgementId(String acknowledgementId) {
        this.acknowledgementId = acknowledgementId;
    }
    public void setPayload(AcknowledgementEvent payload) {
        this.payload = payload;
    }
    @Override
    public String getAcknowledgementId() {
        return acknowledgementId;
    }
    @Override
    public AcknowledgementEvent getPayload() {
        return payload;
    }
}
