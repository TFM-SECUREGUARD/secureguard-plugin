package com.secureguard.model;

/**
 * Enum para las categorías OWASP Top 10 2021
 * Mapea directamente con las categorías del modelo entrenado
 */
public enum OWASPCategory {
    A01_BROKEN_ACCESS_CONTROL("A01:2021", "Broken Access Control",
            "Fallas en el control de acceso que permiten a usuarios no autorizados acceder a recursos protegidos"),

    A02_CRYPTOGRAPHIC_FAILURES("A02:2021", "Cryptographic Failures",
            "Uso inadecuado o ausencia de criptografía para proteger datos sensibles"),

    A03_INJECTION("A03:2021", "Injection",
            "Inyección de código malicioso (SQL, NoSQL, OS Command, LDAP)"),

    A04_INSECURE_DESIGN("A04:2021", "Insecure Design",
            "Fallas fundamentales en el diseño de la aplicación"),

    A05_SECURITY_MISCONFIGURATION("A05:2021", "Security Misconfiguration",
            "Configuraciones inseguras en aplicaciones, frameworks, servidores"),

    A06_VULNERABLE_COMPONENTS("A06:2021", "Vulnerable and Outdated Components",
            "Uso de componentes con vulnerabilidades conocidas"),

    A07_AUTHENTICATION_FAILURES("A07:2021", "Identification and Authentication Failures",
            "Fallas en la implementación de autenticación y gestión de sesiones"),

    A08_SOFTWARE_INTEGRITY_FAILURES("A08:2021", "Software and Data Integrity Failures",
            "Fallas en la verificación de integridad del software y datos"),

    A09_LOGGING_MONITORING_FAILURES("A09:2021", "Security Logging and Monitoring Failures",
            "Registro y monitoreo insuficiente de eventos de seguridad"),

    A10_SSRF("A10:2021", "Server-Side Request Forgery (SSRF)",
            "Permite a atacantes hacer solicitudes desde el servidor a recursos internos"),

    NONE("NONE", "No Vulnerability", "Código seguro sin vulnerabilidades detectadas");

    private final String code;
    private final String title;
    private final String description;

    OWASPCategory(String code, String title, String description) {
        this.code = code;
        this.title = title;
        this.description = description;
    }

    public String getCode() {
        return code;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }

    public String getDisplayName() {
        return code + " - " + title;
    }

    /**
     * Convierte la categoría del modelo Python a enum
     */
    public static OWASPCategory fromModelCategory(String modelCategory) {
        if (modelCategory == null || modelCategory.isEmpty()) {
            return NONE;
        }

        // Mapeo basado en las categorías del dataset
        switch (modelCategory.toLowerCase()) {
            case "injection":
            case "sql_injection":
            case "command_injection":
                return A03_INJECTION;

            case "broken_access_control":
            case "path_traversal":
                return A01_BROKEN_ACCESS_CONTROL;

            case "cryptographic_failures":
            case "weak_crypto":
                return A02_CRYPTOGRAPHIC_FAILURES;

            case "insecure_design":
                return A04_INSECURE_DESIGN;

            case "security_misconfiguration":
            case "xxe":
                return A05_SECURITY_MISCONFIGURATION;

            case "vulnerable_components":
                return A06_VULNERABLE_COMPONENTS;

            case "authentication_failures":
            case "broken_authentication":
                return A07_AUTHENTICATION_FAILURES;

            case "software_integrity_failures":
            case "insecure_deserialization":
                return A08_SOFTWARE_INTEGRITY_FAILURES;

            case "logging_monitoring_failures":
            case "insufficient_logging":
                return A09_LOGGING_MONITORING_FAILURES;

            case "ssrf":
            case "server_side_request_forgery":
                return A10_SSRF;

            default:
                return NONE;
        }
    }

    /**
     * Obtiene el nivel de severidad basado en la categoría
     */
    public Severity getDefaultSeverity() {
        switch (this) {
            case A03_INJECTION:
            case A01_BROKEN_ACCESS_CONTROL:
            case A10_SSRF:
                return Severity.CRITICAL;

            case A02_CRYPTOGRAPHIC_FAILURES:
            case A07_AUTHENTICATION_FAILURES:
            case A08_SOFTWARE_INTEGRITY_FAILURES:
                return Severity.HIGH;

            case A05_SECURITY_MISCONFIGURATION:
            case A06_VULNERABLE_COMPONENTS:
                return Severity.MEDIUM;

            case A04_INSECURE_DESIGN:
            case A09_LOGGING_MONITORING_FAILURES:
                return Severity.LOW;

            default:
                return Severity.NONE;
        }
    }
}