package com.example.capstone.parser.service;

import com.example.capstone.parser.model.AlertState;
import com.example.capstone.parser.model.Findings;
import com.example.capstone.parser.model.Severity;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.*;
import java.util.regex.Pattern;


@Service
public class ParserService {

    private final ElasticsearchClientService esService;
    private final ObjectMapper mapper;

    public ParserService(ElasticsearchClientService esService) {
        this.esService = esService;
        this.mapper = new ObjectMapper();
    }

    public void parseFileAndIndex(String filePath) {
        try {
            // 1) read as array of alerts
            List<Map<String,Object>> rawAlerts = mapper.readValue(
                    new File(filePath),
                    new TypeReference<List<Map<String,Object>>>() {}
            );

            // 2) deduce tool type
            String toolType = deduceToolType(filePath);

            System.out.println("Parsing " + rawAlerts.size()
                    + " alerts for tool " + toolType);

            // optionally parse owner/repo
            String[] or = parseOwnerRepoFromPath(filePath);
            String parsedOwner = or[0];
            String parsedRepo = or[1];

            // 3) for each raw alert => convert => deduplicate
            for (Map<String,Object> alert : rawAlerts) {
                Findings f = convertToFindings(toolType, alert);

                // store owner/repo in additionalData if you want
                Map<String,Object> addData = f.getAdditionalData() != null
                        ? f.getAdditionalData()
                        : new HashMap<>();
                addData.put("owner", parsedOwner);
                addData.put("repo", parsedRepo);
                f.setAdditionalData(addData);

                // run deduplicate logic
                deduplicateAndStore(f);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * deduplicateAndStore:
     *   1) fetch all existing docs for same toolType
     *   2) for each existing doc, compare composite-key hash
     *      if match => compare updatable hash => skip or update
     *   3) if no existing doc matches => index new
     *
     * This method does NOT store composite key or hash in ES.
     * Everything is computed on the fly.
     */
    private void deduplicateAndStore(Findings newDoc) {
        // compute newDoc's compositeKey hash
        String newCompositeHash = computeCompositeKeyHash(newDoc);

        // fetch all existing docs for the same tool type
        List<Findings> existingDocs = esService.findAllByToolType(newDoc.getToolType());

        for (Findings oldDoc : existingDocs) {
            String oldCompositeHash = computeCompositeKeyHash(oldDoc);
            if (Objects.equals(oldCompositeHash, newCompositeHash)) {
                // composite match => check updatable fields
                String newUpdatableHash = computeUpdatableHash(newDoc);
                String oldUpdatableHash = computeUpdatableHash(oldDoc);

                if (Objects.equals(newUpdatableHash, oldUpdatableHash)) {
                    // exact duplicate => skip
                    System.out.println("Skipping duplicate => " + newCompositeHash);
                    return; // done
                } else {
                    // updated => preserve old doc's ID
                    newDoc.setId(oldDoc.getId());
                    // we might want to override 'updatedAt' to now, if you want
                    // or rely on the newDoc's updatedAt from GH
                    esService.updateFindings(newDoc);
                    System.out.println("Updated => " + newCompositeHash);
                    return; // done
                }
            }
        }

        // if we get here => no match => new doc
        newDoc.setId(UUID.randomUUID().toString());
        esService.indexFindings(newDoc);
        System.out.println("Indexed new doc => " + newCompositeHash);
    }

    /**
     * Composite key = "alertNumber + title"
     * We do NOT store or index it. We compute on the fly for new & old docs.
     */
    private String computeCompositeKeyHash(Findings f) {
        // e.g. f.getAlertNumber() + f.getTitle()
        String composite = (f.getAlertNumber() != null ? f.getAlertNumber() : "")
                + "||"
                + (f.getTitle() != null ? f.getTitle() : "");
        // hash it
        return String.valueOf(composite.hashCode());
    }

    /**
     * Updatable fields => severity, state, updatedAt, etc.
     * Possibly also tool-specific logic
     */
    private String computeUpdatableHash(Findings f) {
        StringBuilder sb = new StringBuilder();
        // minimal example
        if (f.getSeverity() != null) sb.append(f.getSeverity()).append("|");
        if (f.getState() != null) sb.append(f.getState()).append("|");
        if (f.getUpdatedAt() != null) sb.append(f.getUpdatedAt());

        // you can do tool-specific
        // e.g. if CODE_SCANNING => ...
        // if DEPENDABOT => ...
        return String.valueOf(sb.toString().hashCode());
    }

    private String deduceToolType(String filePath) {
        String lower = filePath.toLowerCase();
        if (lower.contains("code_scanning")) {
            return "CODE_SCANNING";
        } else if (lower.contains("dependabot")) {
            return "DEPENDABOT";
        } else if (lower.contains("secret_scanning")) {
            return "SECRET_SCANNING";
        }
        return "UNKNOWN_TOOL";
    }

    private Findings convertToFindings(String toolType, Map<String,Object> alert) {
        Findings f = new Findings();
        f.setId(UUID.randomUUID().toString());
        f.setToolType(toolType);

        // e.g. read 'number'
        Object numberObj = alert.get("number");
        String alertNum = (numberObj != null) ? numberObj.toString() : "";
        f.setAlertNumber(alertNum);

        f.setCreatedAt(safeString(alert.get("created_at")));
        f.setUpdatedAt(safeString(alert.get("updated_at")));
        f.setUrl(safeString(alert.get("html_url")));

//        String rawState = safeString(alert.get("state"));
//        f.setState(AlertState.fromRaw(rawState));

        String rawState = safeString(alert.get("state"));

        // We also read "dismissed_reason" if present => "false positive", etc.
        String rawDismissedReason = safeString(alert.get("dismissed_reason"));

        // Now we call the new fromRaw(...) that uses toolType + reason
        AlertState finalState = AlertState.fromRaw(rawState, toolType, rawDismissedReason);
        f.setState(finalState);

        switch (toolType) {
            case "CODE_SCANNING":
                fillCodeScanningData(f, alert);
                break;
            case "DEPENDABOT":
                fillDependabotData(f, alert);
                break;
            case "SECRET_SCANNING":
                fillSecretScanningData(f, alert);
                break;
            default:
                f.setSeverity(Severity.MEDIUM);
                f.setTitle("Unknown Alert");
                f.setDescription("");
                f.setCve("");
                f.setCwe("");
                f.setCvss("");
                f.setLocation("");
        }
        return f;
    }

    private void fillCodeScanningData(Findings f, Map<String,Object> alert) {
        String rawSeverity = safeString(getNested(alert, "rule", "security_severity_level"));
        if (rawSeverity.isEmpty()) {
            rawSeverity = safeString(getNested(alert, "rule", "severity"));
        }
        f.setSeverity(Severity.fromRaw(rawSeverity));

        f.setTitle(safeString(getNested(alert, "rule", "description")));
        f.setDescription(safeString(getNested(alert, "rule", "full_description")));

        Object path = getNested(alert, "most_recent_instance", "location", "path");
        f.setLocation(path != null ? path.toString() : "");

        // parse cwe
        Object tagsObj = getNested(alert, "rule", "tags");
        f.setCwe(parseCweFromTags(tagsObj));

        f.setCve("");
        f.setCvss("");
    }

    private String parseCweFromTags(Object tagsObj) {
        if (tagsObj instanceof List) {
            List<?> list = (List<?>) tagsObj;
            List<String> cwes = new ArrayList<>();
            for (Object item : list) {
                if (item instanceof String) {
                    String tag = ((String) item).toLowerCase();
                    int idx = tag.indexOf("cwe-");
                    if (idx >= 0) {
                        String cwePart = tag.substring(idx).toUpperCase();
                        cwes.add(cwePart);
                    }
                }
            }
            if (!cwes.isEmpty()) {
                return String.join(", ", cwes);
            }
        }
        return "";
    }

    private void fillDependabotData(Findings f, Map<String,Object> alert) {
        String rawSeverity = safeString(getNested(alert, "security_advisory", "severity"));
        f.setSeverity(Severity.fromRaw(rawSeverity));

        f.setCve(safeString(getNested(alert, "security_advisory", "cve_id")));
        f.setTitle(safeString(getNested(alert, "security_advisory", "summary")));
        f.setDescription(safeString(getNested(alert, "security_advisory", "description")));
        f.setCwe(parseCwe(getNested(alert, "security_advisory", "cwes")));

        String cvssVal = safeString(getNested(alert, "security_advisory", "cvss", "score"));
        f.setCvss(cvssVal);

        String manifest = safeString(getNested(alert, "dependency", "manifest_path"));
        if (!manifest.isEmpty()) {
            f.setLocation(manifest);
        } else {
            f.setLocation(safeString(getNested(alert, "dependency", "package", "name")));
        }
    }

    private void fillSecretScanningData(Findings f, Map<String,Object> alert) {
        f.setSeverity(Severity.HIGH);
        f.setTitle("Secret Scanning Alert");
        f.setDescription("");
        f.setCve("");
        f.setCwe("");
        f.setCvss("");
        f.setLocation("");
    }

    // Helpers

    private Object getNested(Map<String,Object> map, String... path) {
        Object current = map;
        for (String p : path) {
            if (!(current instanceof Map)) return null;
            current = ((Map)current).get(p);
            if (current == null) return null;
        }
        return current;
    }

    private String parseCwe(Object cwesObj) {
        if (cwesObj instanceof List) {
            List<?> list = (List<?>) cwesObj;
            if (!list.isEmpty()) {
                Object first = list.get(0);
                if (first instanceof Map) {
                    Object cweId = ((Map)first).get("cwe_id");
                    return cweId != null ? cweId.toString() : "";
                }
            }
        }
        return "";
    }

    private String safeString(Object val) {
        return val != null ? val.toString() : "";
    }

    private String[] parseOwnerRepoFromPath(String filePath) {
        File f = new File(filePath);
        String parent = f.getParent();
        String sepRegex = Pattern.quote(File.separator);
        String[] parts = parent.split(sepRegex);

        String lastFolder = parts[parts.length - 2];
        return lastFolder.split("-", 2);
    }
}


