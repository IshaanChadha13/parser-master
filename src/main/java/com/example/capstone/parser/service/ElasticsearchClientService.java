package com.example.capstone.parser.service;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch._types.query_dsl.Query;
import co.elastic.clients.elasticsearch.core.*;
import co.elastic.clients.elasticsearch.core.search.Hit;
import com.example.capstone.parser.model.Findings;
import com.example.capstone.parser.repository.TenantRepository;
import com.example.capstone.parser.model.TenantEntity; // or wherever your TenantEntity is
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class ElasticsearchClientService {

    private final ElasticsearchClient esClient;
    private final TenantRepository tenantRepository;

    public ElasticsearchClientService(ElasticsearchClient esClient, TenantRepository tenantRepository) {
        this.esClient = esClient;
        this.tenantRepository = tenantRepository;
    }

    /**
     * Index a new Findings document into the ES index that belongs to the tenant.
     * The index name is read from the tenant table (TenantEntity.esIndex).
     */
    public void indexFindings(Long tenantId, Findings findings) {
        try {
            String esIndex = getTenantEsIndex(tenantId);

            String docId = (findings.getId() != null && !findings.getId().isEmpty())
                    ? findings.getId()
                    : UUID.randomUUID().toString();

            IndexRequest<Findings> req = IndexRequest.of(i -> i
                    .index(esIndex)
                    .id(docId)
                    .document(findings)
            );

            IndexResponse resp = esClient.index(req);
            System.out.println("Indexed doc ID: " + resp.id() + " in index: " + esIndex);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Update (re-index) an existing doc in the tenant’s ES index,
     * using doc.getId() as the ES document _id.
     */
    public void updateFindings(Long tenantId, Findings findings) {
        if (findings.getId() == null || findings.getId().isEmpty()) {
            System.out.println("updateFindings called but no doc ID found!");
            return;
        }
        try {
            String esIndex = getTenantEsIndex(tenantId);

            IndexRequest<Findings> req = IndexRequest.of(i -> i
                    .index(esIndex)
                    .id(findings.getId())
                    .document(findings)
            );
            IndexResponse resp = esClient.index(req);
            System.out.println("Updated doc => ID: " + findings.getId()
                    + " in index: " + esIndex);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Fetch all docs of the given toolType from the tenant’s ES index.
     * For dedup logic, we do a term query on "toolType.keyword".
     */
    public List<Findings> findAllByTenantAndToolType(Long tenantId, String toolType) {
        try {
            String esIndex = getTenantEsIndex(tenantId);

            Query toolTypeTerm = Query.of(q -> q.term(t ->
                    t.field("toolType.keyword").value(toolType)
            ));

            SearchRequest req = SearchRequest.of(s -> s
                    .index(esIndex)
                    .query(toolTypeTerm)
                    .size(10000)  // naive upper limit
            );

            SearchResponse<Findings> res = esClient.search(req, Findings.class);
            List<Hit<Findings>> hits = res.hits().hits();

            List<Findings> results = new ArrayList<>();
            for (Hit<Findings> h : hits) {
                Findings f = h.source();
                if (f != null) {
                    // Set the doc's ID from the ES _id
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

    /**
     * Helper: fetches the tenant’s esIndex from the DB. If none found, throw an exception or fallback.
     */
    private String getTenantEsIndex(Long tenantId) {
        Optional<TenantEntity> optTenant = tenantRepository.findById(tenantId);
        if (optTenant.isEmpty()) {
            throw new IllegalStateException("No tenant found with id=" + tenantId);
        }
        TenantEntity tenant = optTenant.get();
        String esIndex = tenant.getEsIndex();  // or tenant.getName() if esIndex is null
        if (esIndex == null || esIndex.isBlank()) {
            // fallback to the tenant name or any default if you prefer
            esIndex = tenant.getName();
            if (esIndex == null || esIndex.isBlank()) {
                throw new IllegalStateException("Tenant " + tenantId + " has no esIndex or name set.");
            }
        }
        return esIndex;
    }
}
