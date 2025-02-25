package com.example.capstone.parser.producer;

import com.example.capstone.parser.dto.ParseAcknowledgement;
import com.example.capstone.parser.model.AcknowledgementEvent;
import com.example.capstone.parser.model.AcknowledgementStatus;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

@Service
public class AcknowledgementProducer {

    @Value("${kafka.topics.job-acknowledgement-topic}")
    private String jobAckTopic;

    private final KafkaTemplate<String, String> kafkaTemplate;
    private final ObjectMapper objectMapper;

    public AcknowledgementProducer(KafkaTemplate<String, String> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Sends a ParseAcknowledgement to the job-acknowledgement-topic.
     *
     * @param jobId   the ID (eventId) of the job as received from JFC
     * @param success true if the parser completed its job successfully, false otherwise
     */
    public void sendParseAcknowledgement(String jobId, boolean success) {
        try {
            AcknowledgementEvent ackEvent = new AcknowledgementEvent(jobId);
            ackEvent.setStatus(success ? AcknowledgementStatus.SUCCESS : AcknowledgementStatus.FAILURE);
            ParseAcknowledgement ack = new ParseAcknowledgement(null, ackEvent);
            String json = objectMapper.writeValueAsString(ack);
            kafkaTemplate.send(jobAckTopic, json);
            System.out.println("Parser sent ParseAcknowledgement: " + json);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
