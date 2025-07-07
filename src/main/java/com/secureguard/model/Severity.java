package com.secureguard.model;

import com.intellij.codeInspection.ProblemHighlightType;
import com.intellij.ui.JBColor;
import java.awt.Color;

/**
 * Niveles de severidad para las vulnerabilidades detectadas
 */
public enum Severity {
    CRITICAL(5, "Critical",
            new JBColor(new Color(220, 20, 60), new Color(255, 69, 58)),
            ProblemHighlightType.ERROR),

    HIGH(4, "High",
            new JBColor(new Color(255, 140, 0), new Color(255, 159, 10)),
            ProblemHighlightType.GENERIC_ERROR_OR_WARNING),

    MEDIUM(3, "Medium",
            new JBColor(new Color(255, 215, 0), new Color(255, 214, 10)),
            ProblemHighlightType.WEAK_WARNING),

    LOW(2, "Low",
            new JBColor(new Color(30, 144, 255), new Color(10, 132, 255)),
            ProblemHighlightType.INFORMATION),

    INFO(1, "Info",
            new JBColor(new Color(128, 128, 128), new Color(152, 152, 157)),
            ProblemHighlightType.INFORMATION),

    NONE(0, "None",
            JBColor.GREEN,
            ProblemHighlightType.INFORMATION);

    private final int level;
    private final String displayName;
    private final Color color;
    private final ProblemHighlightType highlightType;

    Severity(int level, String displayName, Color color, ProblemHighlightType highlightType) {
        this.level = level;
        this.displayName = displayName;
        this.color = color;
        this.highlightType = highlightType;
    }

    public int getLevel() {
        return level;
    }

    public String getDisplayName() {
        return displayName;
    }

    public Color getColor() {
        return color;
    }

    public ProblemHighlightType getHighlightType() {
        return highlightType;
    }

    public boolean isHigherThan(Severity other) {
        return this.level > other.level;
    }

    /**
     * Obtiene la severidad basada en el score de confianza del modelo
     * @param confidence Score de confianza (0.0 - 1.0)
     * @param isVulnerable Si el código es vulnerable o no
     * @return Nivel de severidad apropiado
     */
    public static Severity fromConfidence(double confidence, boolean isVulnerable) {
        if (!isVulnerable) {
            return NONE;
        }

        if (confidence >= 0.9) {
            return CRITICAL;
        } else if (confidence >= 0.75) {
            return HIGH;
        } else if (confidence >= 0.6) {
            return MEDIUM;
        } else if (confidence >= 0.5) {
            return LOW;
        } else {
            return INFO;
        }
    }
}