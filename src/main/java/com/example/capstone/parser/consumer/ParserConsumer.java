package com.example.capstone.parser.consumer;

import com.example.capstone.parser.dto.ParserMessageEvent;
import com.example.capstone.parser.model.ParserMessage;
import com.example.capstone.parser.service.ParserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;

@Service
public class ParserConsumer {

    private final ParserService parserService;
    private final ObjectMapper objectMapper;

    public ParserConsumer(ParserService parserService, ObjectMapper objectMapper) {
        this.parserService = parserService;
        this.objectMapper = objectMapper;
    }

    @KafkaListener(topics = "${kafka.topics.jfc-parser-topic}")
    public void onMessage(String message) {
        try {
            ParserMessageEvent event = objectMapper.readValue(message, ParserMessageEvent.class);

            String eventId = event.getEventId();

            // 2) Extract the ParserMessage payload
            ParserMessage pm = event.getPayload();

            Long tenantId  = pm.getTenantId();
            String filePath = pm.getFilePath();
            String toolType = pm.getToolType();

            System.out.println("ParserConsumer received => eventType=" + event.getType() +
                    ", tenantId=" + tenantId + ", filePath=" + filePath + ", toolType= " + toolType);

            // 3) Pass both tenantId & filePath to the parserService
            parserService.parseFileAndIndex(tenantId, filePath, toolType, eventId);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
