package com.secureguard.model;

import com.intellij.psi.PsiElement;
import com.intellij.psi.PsiFile;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.time.LocalDateTime;
import java.util.Objects;
import java.util.UUID;

/**
 * Representa una vulnerabilidad de seguridad detectada por el modelo
 */
public class SecurityIssue {
    private final String id;
    private final OWASPCategory category;
    private final Severity severity;
    private final String description;
    private final String recommendation;
    private final PsiElement element;
    private final PsiFile file;
    private final int lineNumber;
    private final double confidence;
    private final LocalDateTime detectedAt;
    private final String codeSnippet;
    private final String vulnerabilityType;

    // Constructor principal
    public SecurityIssue(@NotNull OWASPCategory category,
                         @NotNull Severity severity,
                         @NotNull String description,
                         @NotNull String recommendation,
                         @NotNull PsiElement element,
                         double confidence,
                         @NotNull String vulnerabilityType) {
        this.id = UUID.randomUUID().toString();
        this.category = category;
        this.severity = severity;
        this.description = description;
        this.recommendation = recommendation;
        this.element = element;
        this.file = element.getContainingFile();
        this.lineNumber = calculateLineNumber(element);
        this.confidence = confidence;
        this.detectedAt = LocalDateTime.now();
        this.codeSnippet = extractCodeSnippet(element);
        this.vulnerabilityType = vulnerabilityType;
    }

    private int calculateLineNumber(PsiElement element) {
        if (element.getContainingFile() != null &&
                element.getContainingFile().getViewProvider().getDocument() != null) {
            int offset = element.getTextOffset();
            return element.getContainingFile().getViewProvider().getDocument()
                    .getLineNumber(offset) + 1;
        }
        return -1;
    }

    private String extractCodeSnippet(PsiElement element) {
        String text = element.getText();
        if (text == null) {
            return "";
        }
        if (text.length() > 200) {
            return text.substring(0, 197) + "...";
        }
        return text;
    }

    /**
     * Genera una sugerencia de corrección basada en la categoría OWASP
     */
    public String generateQuickFix() {
        switch (category) {
            case A03_INJECTION:
                return generateInjectionFix();
            case A01_BROKEN_ACCESS_CONTROL:
                return generateAccessControlFix();
            case A02_CRYPTOGRAPHIC_FAILURES:
                return generateCryptoFix();
            case A10_SSRF:
                return generateSSRFFix();
            case A07_AUTHENTICATION_FAILURES:
                return generateAuthFix();
            case A05_SECURITY_MISCONFIGURATION:
                return generateConfigFix();
            default:
                return recommendation;
        }
    }

    private String generateInjectionFix() {
        if (codeSnippet.contains("Statement") && !codeSnippet.contains("PreparedStatement")) {
            return "Replace Statement with PreparedStatement:\n\n" +
                    "// Vulnerable code:\n" +
                    "Statement stmt = connection.createStatement();\n" +
                    "String query = \"SELECT * FROM users WHERE id = \" + userId;\n\n" +
                    "// Secure code:\n" +
                    "String query = \"SELECT * FROM users WHERE id = ?\";\n" +
                    "PreparedStatement pstmt = connection.prepareStatement(query);\n" +
                    "pstmt.setInt(1, userId);";
        }
        return "Use parameterized queries or prepared statements to prevent injection.";
    }

    private String generateAccessControlFix() {
        return "Implement proper authorization checks:\n\n" +
                "@PreAuthorize(\"hasRole('USER') and #userId == authentication.principal.id\")\n" +
                "public void updateUserProfile(Long userId, UserProfile profile) {\n" +
                "    // Method implementation\n" +
                "}";
    }

    private String generateCryptoFix() {
        if (codeSnippet.contains("MD5") || codeSnippet.contains("SHA1")) {
            return "Replace weak hashing algorithm:\n\n" +
                    "// Vulnerable: MD5/SHA1\n" +
                    "MessageDigest md = MessageDigest.getInstance(\"MD5\");\n\n" +
                    "// Secure: Use bcrypt for passwords\n" +
                    "BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();\n" +
                    "String hashedPassword = encoder.encode(plainPassword);";
        }
        return "Use strong encryption algorithms (AES-256) and secure key management.";
    }

    private String generateSSRFFix() {
        return "Validate and sanitize URL inputs:\n\n" +
                "private static final Set<String> ALLOWED_HOSTS = Set.of(\n" +
                "    \"api.trusted.com\",\n" +
                "    \"internal.service.com\"\n" +
                ");\n\n" +
                "public void fetchData(String userUrl) throws SecurityException {\n" +
                "    URL url = new URL(userUrl);\n" +
                "    if (!ALLOWED_HOSTS.contains(url.getHost())) {\n" +
                "        throw new SecurityException(\"Host not allowed: \" + url.getHost());\n" +
                "    }\n" +
                "    // Proceed with the request\n" +
                "}";
    }

    private String generateAuthFix() {
        return "Implement secure session management:\n\n" +
                "// Configure session security\n" +
                "http.sessionManagement()\n" +
                "    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)\n" +
                "    .invalidSessionUrl(\"/login\")\n" +
                "    .maximumSessions(1)\n" +
                "    .maxSessionsPreventsLogin(true)\n" +
                "    .and()\n" +
                "    .sessionFixation().migrateSession();";
    }

    private String generateConfigFix() {
        return "Apply secure configuration:\n\n" +
                "// Disable dangerous features\n" +
                "System.setProperty(\"javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING\", \"true\");\n" +
                "// Set secure headers\n" +
                "response.setHeader(\"X-Content-Type-Options\", \"nosniff\");\n" +
                "response.setHeader(\"X-Frame-Options\", \"DENY\");";
    }

    // Getters
    public String getId() { return id; }
    public OWASPCategory getCategory() { return category; }
    public Severity getSeverity() { return severity; }
    public String getDescription() { return description; }
    public String getRecommendation() { return recommendation; }
    public PsiElement getElement() { return element; }
    public PsiFile getFile() { return file; }
    public int getLineNumber() { return lineNumber; }
    public double getConfidence() { return confidence; }
    public LocalDateTime getDetectedAt() { return detectedAt; }
    public String getCodeSnippet() { return codeSnippet; }
    public String getVulnerabilityType() { return vulnerabilityType; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecurityIssue that = (SecurityIssue) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return String.format("SecurityIssue{category=%s, severity=%s, line=%d, confidence=%.2f}",
                category.getCode(), severity.getDisplayName(), lineNumber, confidence);
    }
}