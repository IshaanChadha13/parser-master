package com.example.capstone.parser.model;

public interface Event<T> {

    EventTypes getType();
    T getPayload();
    String getEventId();
}
