package com.example.capstone.parser.dto;

import com.example.capstone.parser.model.Event;
import com.example.capstone.parser.model.EventTypes;
import com.example.capstone.parser.model.ParserMessage;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ParserMessageEvent implements Event<ParserMessage> {

    private String eventId;
    private ParserMessage payload;

    public ParserMessageEvent(ParserMessage payload, String eventId) {
        this.payload = payload;
        this.eventId = eventId;
    }

    public ParserMessageEvent() {

    }

    public void setPayload(ParserMessage payload) {
        this.payload = payload;
    }

    @Override
    public String getEventId() {
        return eventId;
    }

    public void setEventId(String eventId) {
        this.eventId = eventId;
    }

    @Override
    public EventTypes getType() {
        return EventTypes.SCAN_PARSE;
    }

    @Override
    public ParserMessage getPayload() {
        return payload;
    }
}
