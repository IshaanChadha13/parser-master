package com.example.capstone.parser.model;

public class ParserMessage {

    public Long tenantId;
    public String filePath;
    public String toolType;

    public ParserMessage() {}
    public ParserMessage(Long tenantId, String filePath, String toolType) {
        this.tenantId = tenantId;
        this.filePath = filePath;
        this.toolType = toolType;
    }

    public String getToolType() {
        return toolType;
    }

    public void setToolType(String toolType) {
        this.toolType = toolType;
    }

    public Long getTenantId() {
        return tenantId;
    }

    public void setTenantId(Long tenantId) {
        this.tenantId = tenantId;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }
}
