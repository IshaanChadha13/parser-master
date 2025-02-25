package com.example.capstone.parser.model;

public interface Acknowledgement<T> {

    String getAcknowledgementId();
    T getPayload();
}
