package com.example.capstone.parser.consumer;

import com.example.capstone.parser.service.ParserService;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;

@Service
public class ParserConsumer {

    private final ParserService parserService;

    public ParserConsumer(ParserService parserService) {
        this.parserService = parserService;
    }

    @KafkaListener(topics = "${kafka.topics.parser-topic}")
    public void onMessage(String filePath) {
        System.out.println("ParserConsumer received file path: " + filePath);
        parserService.parseFileAndIndex(filePath);
    }
}
