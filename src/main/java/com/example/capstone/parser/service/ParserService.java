package com.example.capstone.parser.service;

import com.example.capstone.parser.model.AlertState;
import com.example.capstone.parser.model.Findings;
import com.example.capstone.parser.model.Severity;
import com.example.capstone.parser.producer.AcknowledgementProducer;
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
    private final AcknowledgementProducer acknowledgementProducer; // New field

    public ParserService(ElasticsearchClientService esService, AcknowledgementProducer acknowledgementProducer) {
        this.esService = esService;
        this.acknowledgementProducer = acknowledgementProducer;
        this.mapper = new ObjectMapper();
    }

    /**
     * Parses the file and indexes the alerts.
     *
     * @param tenantId the tenant identifier
     * @param filePath the path to the alerts file
     * @param toolType the type of tool (e.g., CODE_SCANNING, DEPENDABOT, SECRET_SCANNING)
     * @param eventId  the original eventId for this parse job (to be used in the ack)
     */
    public void parseFileAndIndex(Long tenantId, String filePath, String toolType, String eventId) {
        boolean success = false;
        try {
            // 1) Read raw alerts from file
            List<Map<String, Object>> rawAlerts = mapper.readValue(
                    new File(filePath),
                    new TypeReference<>() {}
            );

            // 2) Optionally parse owner/repo from folder name
            String[] ownerRepo = parseOwnerRepoFromPath(filePath);
            String parsedOwner = ownerRepo[0];
            String parsedRepo  = ownerRepo[1];

            System.out.println("ParserService => Found " + rawAlerts.size()
                    + " alerts for tool " + toolType
                    + " in tenant " + tenantId
                    + " => (" + parsedOwner + "/" + parsedRepo + ")");

            // 3) Convert, deduplicate, and store each alert
            for (Map<String, Object> alert : rawAlerts) {
                Findings f = convertToFindings(toolType, alert);

                // Include tenantId, owner, repo in additionalData
                Map<String, Object> addData = (f.getAdditionalData() != null)
                        ? f.getAdditionalData()
                        : new HashMap<>();
                addData.put("tenantId", tenantId);
                addData.put("owner", parsedOwner);
                addData.put("repo", parsedRepo);
                f.setAdditionalData(addData);

                // Deduplicate & store
                deduplicateAndStore(tenantId, f);
            }
            success = true;
        } catch (Exception e) {
            e.printStackTrace();
        } finally {

            try {
                Thread.sleep(10000);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
            }

            acknowledgementProducer.sendParseAcknowledgement(eventId, success);
        }
    }

    private void deduplicateAndStore(Long tenantId, Findings newDoc) {
        String newCompositeHash = computeCompositeKeyHash(newDoc);

        // fetch existing docs for the same tenant + tool type
        List<Findings> existingDocs = esService.findAllByTenantAndToolType(tenantId, newDoc.getToolType());

        for (Findings oldDoc : existingDocs) {
            String oldCompositeHash = computeCompositeKeyHash(oldDoc);
            if (Objects.equals(oldCompositeHash, newCompositeHash)) {
                String newUpdatableHash = computeUpdatableHash(newDoc);
                String oldUpdatableHash = computeUpdatableHash(oldDoc);

                if (Objects.equals(newUpdatableHash, oldUpdatableHash)) {
                    System.out.println("Skipping duplicate => " + newCompositeHash);
                    return;
                } else {
                    newDoc.setId(oldDoc.getId());
                    esService.updateFindings(tenantId, newDoc);
                    System.out.println("Updated => " + newCompositeHash);
                    return;
                }
            }
        }

        newDoc.setId(UUID.randomUUID().toString());
        esService.indexFindings(tenantId, newDoc);
        System.out.println("Indexed new doc => " + newCompositeHash);
    }

    private String computeCompositeKeyHash(Findings f) {
        String composite = (f.getAlertNumber() != null ? f.getAlertNumber() : "")
                + "||"
                + (f.getTitle() != null ? f.getTitle() : "");
        return String.valueOf(composite.hashCode());
    }

    private String computeUpdatableHash(Findings f) {
        StringBuilder sb = new StringBuilder();
        if (f.getSeverity() != null) sb.append(f.getSeverity()).append("|");
        if (f.getState() != null) sb.append(f.getState()).append("|");
        if (f.getUpdatedAt() != null) sb.append(f.getUpdatedAt());
        return String.valueOf(sb.toString().hashCode());
    }

    // ----------------------------------------------------------------------
    // Tool-specific conversion methods
    // ----------------------------------------------------------------------

    private Findings convertToFindings(String toolType, Map<String, Object> alert) {
        Findings f = new Findings();
        f.setId(UUID.randomUUID().toString());
        f.setToolType(toolType);
        f.setTicketId(null);

        Object numberObj = alert.get("number");
        String alertNum = (numberObj != null) ? numberObj.toString() : "";
        f.setAlertNumber(alertNum);

        f.setCreatedAt(safeString(alert.get("created_at")));
        f.setUpdatedAt(safeString(alert.get("updated_at")));
        f.setUrl(safeString(alert.get("html_url")));

        String rawState = safeString(alert.get("state"));
        String rawDismissedReason = safeString(alert.get("dismissed_reason"));
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

    private void fillCodeScanningData(Findings f, Map<String, Object> alert) {
        String rawSeverity = safeString(getNested(alert, "rule", "security_severity_level"));
        if (rawSeverity.isEmpty()) {
            rawSeverity = safeString(getNested(alert, "rule", "severity"));
        }
        f.setSeverity(Severity.fromRaw(rawSeverity));
        f.setTitle(safeString(getNested(alert, "rule", "description")));
        f.setDescription(safeString(getNested(alert, "rule", "full_description")));
        Object path = getNested(alert, "most_recent_instance", "location", "path");
        f.setLocation(path != null ? path.toString() : "");
        Object tagsObj = getNested(alert, "rule", "tags");
        f.setCwe(parseCweFromTags(tagsObj));
        f.setCve("");
        f.setCvss("");
    }

    private void fillDependabotData(Findings f, Map<String, Object> alert) {
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

    private void fillSecretScanningData(Findings f, Map<String, Object> alert) {
        Boolean publiclyLeaked = (alert.get("publicly_leaked") instanceof Boolean)
                ? (Boolean) alert.get("publicly_leaked")
                : false;
        f.setSeverity(Boolean.TRUE.equals(publiclyLeaked) ? Severity.CRITICAL : Severity.HIGH);
        String secretTypeDisplay = safeString(alert.get("secret_type_display_name"));
        if (secretTypeDisplay.isEmpty()) {
            secretTypeDisplay = safeString(alert.get("secret_type"));
        }
        f.setTitle("Secret Scanning Alert: " + secretTypeDisplay);
        String validity = safeString(alert.get("validity"));
        String resolution = safeString(alert.get("resolution"));
        boolean pushProtectionBypassed = (alert.get("push_protection_bypassed") instanceof Boolean)
                ? (boolean) alert.get("push_protection_bypassed")
                : false;
        String rawSecret = safeString(alert.get("secret"));
        String maskedSecret = rawSecret.isEmpty() ? "" : (rawSecret.length() > 8
                ? rawSecret.substring(0, 8) + "...(masked)"
                : rawSecret);
        StringBuilder descBuilder = new StringBuilder();
        descBuilder.append("Secret Type: ").append(safeString(alert.get("secret_type")))
                .append("; Validity: ").append(validity)
                .append("; Publicly Leaked: ").append(publiclyLeaked)
                .append("; Push Protection Bypassed: ").append(pushProtectionBypassed);
        if (!resolution.isEmpty()) {
            descBuilder.append("; Resolution: ").append(resolution);
        }
        if (!maskedSecret.isEmpty()) {
            descBuilder.append("; Secret (masked): ").append(maskedSecret);
        }
        f.setDescription(descBuilder.toString());
        f.setCve("");
        f.setCwe("");
        f.setCvss("");
        f.setLocation(safeString(alert.get("locations_url")));
    }

    // ----------------------------------------------------------------------
    // File path logic and misc helpers
    // ----------------------------------------------------------------------

    private String[] parseOwnerRepoFromPath(String filePath) {
        File f = new File(filePath);
        String parent = f.getParent();
        String[] pathParts = parent.split(Pattern.quote(File.separator));
        String secondLast = pathParts[pathParts.length - 2];
        int underscoreIdx = secondLast.indexOf("_");
        if (underscoreIdx >= 0) {
            secondLast = secondLast.substring(underscoreIdx + 1);
        }
        int lastDash = secondLast.lastIndexOf("-");
        if (lastDash == -1) {
            return new String[]{"unknownOwner", "unknownRepo"};
        }
        String owner = secondLast.substring(0, lastDash);
        String repo  = secondLast.substring(lastDash + 1);
        return new String[]{ owner, repo };
    }

    private String deduceToolType(String filePath) {
        String lower = filePath.toLowerCase();
        if (lower.contains("code_scanning")) return "CODE_SCANNING";
        if (lower.contains("dependabot")) return "DEPENDABOT";
        if (lower.contains("secret_scanning")) return "SECRET_SCANNING";
        return "UNKNOWN_TOOL";
    }

    private Object getNested(Map<String, Object> map, String... path) {
        Object current = map;
        for (String p : path) {
            if (!(current instanceof Map)) return null;
            current = ((Map) current).get(p);
            if (current == null) return null;
        }
        return current;
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

    private String parseCwe(Object cwesObj) {
        if (cwesObj instanceof List) {
            List<?> list = (List<?>) cwesObj;
            if (!list.isEmpty()) {
                Object first = list.get(0);
                if (first instanceof Map) {
                    Object cweId = ((Map) first).get("cwe_id");
                    return cweId != null ? cweId.toString() : "";
                }
            }
        }
        return "";
    }

    private String safeString(Object val) {
        return val != null ? val.toString() : "";
    }
}
