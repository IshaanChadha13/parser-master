package com.example.capstone.parser.service;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch._types.SortOrder;
import co.elastic.clients.elasticsearch.core.*;
import co.elastic.clients.elasticsearch.core.search.Hit;
import com.example.capstone.parser.model.Findings;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import co.elastic.clients.elasticsearch._types.query_dsl.BoolQuery;
import co.elastic.clients.elasticsearch._types.query_dsl.Query;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class ElasticsearchClientService {

    private final ElasticsearchClient esClient;
    private final String indexName;

    public ElasticsearchClientService(ElasticsearchClient esClient,
                                      @Value("${elasticsearch.index}") String indexName) {
        this.esClient = esClient;
        this.indexName = indexName;
    }

    public void indexFindings(Findings findings) {
        try {
            String docId = (findings.getId() != null && !findings.getId().isEmpty())
                    ? findings.getId()
                    : UUID.randomUUID().toString();

            IndexRequest<Findings> req = IndexRequest.of(i -> i
                    .index(indexName)
                    .id(docId)
                    .document(findings)
            );
            IndexResponse resp = esClient.index(req);
            System.out.println("Indexed doc ID: " + resp.id());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void updateFindings(Findings findings) {
        if (findings.getId() == null || findings.getId().isEmpty()) {
            System.out.println("updateFindings called but no doc ID found!");
            return;
        }
        try {
            IndexRequest<Findings> req = IndexRequest.of(i -> i
                    .index(indexName)
                    .id(findings.getId())
                    .document(findings)
            );
            IndexResponse resp = esClient.index(req);
            System.out.println("Updated doc => ID: " + findings.getId());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Return all docs of the given toolType
     * For dedup logic, we do NOT store or compare any compositeKey or hash.
     * We just fetch all, filter by toolType, no pagination here (caution if large data).
     */
    public List<Findings> findAllByToolType(String toolType) {
        try {
            // We'll do a term query => "toolType.keyword" == toolType
            Query toolTypeTerm = Query.of(q -> q.term(t ->
                    t.field("toolType.keyword").value(toolType)
            ));

            // Possibly limit size or do a scroll if there's a lot
            SearchRequest req = SearchRequest.of(s -> s
                    .index(indexName)
                    .query(toolTypeTerm)
                    .size(10000) // naive upper limit
            );

            SearchResponse<Findings> res = esClient.search(req, Findings.class);
            List<Hit<Findings>> hits = res.hits().hits();

            List<Findings> results = new ArrayList<>();
            for (Hit<Findings> h : hits) {
                Findings f = h.source();
                if (f != null) {
                    f.setId(h.id());
                    results.add(f);
                }
            }
            return results;

        } catch (IOException e) {
            e.printStackTrace();
            return Collections.emptyList();
        }
    }

}
