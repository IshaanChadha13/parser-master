package com.example.capstone.parser.dto;

public class ChangeAlertStateRequest {
    private String owner;
    private String repo;
    private String toolType;         // e.g. CODE_SCANNING
    private String alertNumber;      // GH alert "number"
    private String newState;         // e.g. "OPEN" or "DISMISS"
    private String dismissReason;    // if "DISMISS"

    public ChangeAlertStateRequest() {
    }

    public String getOwner() {
        return owner;
    }

    public void setOwner(String owner) {
        this.owner = owner;
    }

    public String getRepo() {
        return repo;
    }

    public void setRepo(String repo) {
        this.repo = repo;
    }

    public String getToolType() {
        return toolType;
    }

    public void setToolType(String toolType) {
        this.toolType = toolType;
    }

    public String getAlertNumber() {
        return alertNumber;
    }

    public void setAlertNumber(String alertNumber) {
        this.alertNumber = alertNumber;
    }

    public String getNewState() {
        return newState;
    }

    public void setNewState(String newState) {
        this.newState = newState;
    }

    public String getDismissReason() {
        return dismissReason;
    }

    public void setDismissReason(String dismissReason) {
        this.dismissReason = dismissReason;
    }
}