package com.secureguard.analysis;

import com.secureguard.model.OWASPCategory;
import com.secureguard.model.Severity;

import java.util.Map;

/**
 * Calcula la severidad basándose en la categoría OWASP y la confianza
 */
public class SeverityCalculator {

    /**
     * Calcula la severidad apropiada para una vulnerabilidad
     */
    public static Severity calculateSeverity(OWASPCategory category, double confidence, Map<String, Double> features) {
        // Si no es vulnerable
        if (category == OWASPCategory.NONE) {
            return Severity.NONE;
        }

        // Severidad base por categoría
        Severity baseSeverity = getBaseSeverity(category);

        // Ajustar por confianza
        if (confidence < 0.5) {
            return downgrade(baseSeverity);
        } else if (confidence > 0.85) {
            return upgrade(baseSeverity, features);
        }

        return baseSeverity;
    }

    /**
     * Severidad base para cada categoría OWASP
     */
    private static Severity getBaseSeverity(OWASPCategory category) {
        switch (category) {
            // CRÍTICAS por defecto
            case A03_INJECTION:
            case A01_BROKEN_ACCESS_CONTROL:
            case A10_SSRF:
                return Severity.CRITICAL;

            // ALTAS por defecto
            case A02_CRYPTOGRAPHIC_FAILURES:
            case A07_AUTHENTICATION_FAILURES:
            case A08_SOFTWARE_INTEGRITY_FAILURES:
                return Severity.HIGH;

            // MEDIAS por defecto
            case A05_SECURITY_MISCONFIGURATION:
            case A06_VULNERABLE_COMPONENTS:
                return Severity.MEDIUM;

            // BAJAS por defecto
            case A04_INSECURE_DESIGN:
            case A09_LOGGING_MONITORING_FAILURES:
                return Severity.LOW;

            default:
                return Severity.MEDIUM;
        }
    }

    /**
     * Reduce la severidad un nivel
     */
    private static Severity downgrade(Severity severity) {
        switch (severity) {
            case CRITICAL:
                return Severity.HIGH;
            case HIGH:
                return Severity.MEDIUM;
            case MEDIUM:
                return Severity.LOW;
            case LOW:
                return Severity.INFO;
            default:
                return severity;
        }
    }

    /**
     * Aumenta la severidad si hay factores agravantes
     */
    private static Severity upgrade(Severity severity, Map<String, Double> features) {
        // Factores agravantes
        boolean hasUserInput = features.getOrDefault("has_user_input", 0.0) > 0;
        boolean hasNetworkOps = features.getOrDefault("has_network_ops", 0.0) > 0;
        boolean hasDangerousMethods = features.getOrDefault("dangerous_methods_count", 0.0) > 1;

        // Si hay múltiples factores agravantes, aumentar severidad
        int aggravatingFactors = 0;
        if (hasUserInput) aggravatingFactors++;
        if (hasNetworkOps) aggravatingFactors++;
        if (hasDangerousMethods) aggravatingFactors++;

        if (aggravatingFactors >= 2) {
            switch (severity) {
                case LOW:
                    return Severity.MEDIUM;
                case MEDIUM:
                    return Severity.HIGH;
                case HIGH:
                    return Severity.CRITICAL;
                default:
                    return severity;
            }
        }

        return severity;
    }
}