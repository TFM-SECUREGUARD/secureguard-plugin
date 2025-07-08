package com.secureguard.ui;

import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.DialogWrapper;
import com.intellij.ui.JBColor;
import com.intellij.ui.components.JBLabel;
import com.intellij.ui.components.JBScrollPane;
import com.intellij.util.ui.JBUI;
import com.intellij.util.ui.UIUtil;
import com.secureguard.model.SecurityIssue;
import com.secureguard.model.Severity;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.MatteBorder;
import java.awt.*;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Diálogo mejorado para mostrar los resultados del análisis de seguridad
 */
public class SecurityResultsDialog extends DialogWrapper {
    private final String fileName;
    private final List<SecurityIssue> issues;

    public SecurityResultsDialog(@Nullable Project project, String fileName, List<SecurityIssue> issues) {
        super(project);
        this.fileName = fileName;
        this.issues = issues;

        setTitle("SecureGuard - Security Analysis Results");
        setModal(true);
        setResizable(true);

        init();
    }

    @Nullable
    @Override
    protected JComponent createCenterPanel() {
        JPanel mainPanel = new JPanel(new BorderLayout(0, 20));
        mainPanel.setPreferredSize(new Dimension(800, 600));

        // Header
        mainPanel.add(createHeaderPanel(), BorderLayout.NORTH);

        // Results
        mainPanel.add(createResultsPanel(), BorderLayout.CENTER);

        // Summary
        mainPanel.add(createSummaryPanel(), BorderLayout.SOUTH);

        return mainPanel;
    }

    private JPanel createHeaderPanel() {
        JPanel header = new JPanel(new BorderLayout(10, 10));
        header.setBorder(new EmptyBorder(10, 15, 10, 15));

        // Title
        JLabel titleLabel = new JLabel("Security Analysis Results");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 18f));
        header.add(titleLabel, BorderLayout.NORTH);

        // File info
        JPanel fileInfo = new JPanel(new FlowLayout(FlowLayout.LEFT));
        fileInfo.add(new JLabel("File: "));
        JLabel fileLabel = new JLabel(fileName);
        fileLabel.setFont(fileLabel.getFont().deriveFont(Font.BOLD));
        fileInfo.add(fileLabel);

        if (issues.isEmpty()) {
            fileInfo.add(Box.createHorizontalStrut(20));
            JLabel safeLabel = new JLabel("✓ No vulnerabilities detected");
            safeLabel.setForeground(JBColor.GREEN.darker());
            fileInfo.add(safeLabel);
        } else {
            fileInfo.add(Box.createHorizontalStrut(20));
            JLabel foundLabel = new JLabel(String.format("⚠ Found %d potential vulnerabilities", issues.size()));
            foundLabel.setForeground(JBColor.ORANGE);
            fileInfo.add(foundLabel);
        }

        header.add(fileInfo, BorderLayout.CENTER);

        return header;
    }

    private JComponent createResultsPanel() {
        if (issues.isEmpty()) {
            return createNoIssuesPanel();
        }

        JPanel resultsPanel = new JPanel();
        resultsPanel.setLayout(new BoxLayout(resultsPanel, BoxLayout.Y_AXIS));
        resultsPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // Agrupar por severidad
        Map<Severity, List<SecurityIssue>> groupedBySeverity = issues.stream()
                .collect(Collectors.groupingBy(SecurityIssue::getSeverity));

        // Orden de severidad
        Severity[] severityOrder = {
                Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                Severity.LOW, Severity.INFO
        };

        for (Severity severity : severityOrder) {
            List<SecurityIssue> severityIssues = groupedBySeverity.get(severity);
            if (severityIssues != null && !severityIssues.isEmpty()) {
                // Sección de severidad
                JPanel severitySection = createSeveritySection(severity, severityIssues);
                resultsPanel.add(severitySection);
                resultsPanel.add(Box.createVerticalStrut(15));
            }
        }

        // Scroll pane
        JBScrollPane scrollPane = new JBScrollPane(resultsPanel);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

        return scrollPane;
    }

    private JPanel createSeveritySection(Severity severity, List<SecurityIssue> issues) {
        JPanel section = new JPanel(new BorderLayout());
        section.setBorder(new CompoundBorder(
                new MatteBorder(0, 0, 1, 0, UIUtil.getFocusedBorderColor()),
                new EmptyBorder(10, 5, 10, 5)
        ));

        // Header con severidad
        JPanel headerPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));

        // Icono y título de severidad
        JLabel severityLabel = new JLabel(getSeverityIcon(severity) + " " +
                severity.getDisplayName() + " (" + issues.size() + ")");
        severityLabel.setFont(severityLabel.getFont().deriveFont(Font.BOLD, 14f));
        severityLabel.setForeground(severity.getColor());
        headerPanel.add(severityLabel);

        section.add(headerPanel, BorderLayout.NORTH);

        // Lista de issues
        JPanel issuesPanel = new JPanel();
        issuesPanel.setLayout(new BoxLayout(issuesPanel, BoxLayout.Y_AXIS));
        issuesPanel.setBorder(new EmptyBorder(10, 20, 0, 0));

        for (SecurityIssue issue : issues) {
            JPanel issuePanel = createIssuePanel(issue);
            issuesPanel.add(issuePanel);
            issuesPanel.add(Box.createVerticalStrut(10));
        }

        section.add(issuesPanel, BorderLayout.CENTER);

        return section;
    }

    private JPanel createIssuePanel(SecurityIssue issue) {
        JPanel panel = new JPanel(new BorderLayout(10, 5));
        panel.setBorder(new EmptyBorder(5, 10, 5, 10));
        panel.setBackground(UIUtil.getPanelBackground());

        // Info principal
        JPanel infoPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = JBUI.insets(2, 0);

        // Categoría y línea
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1.0;
        JLabel categoryLabel = new JLabel(String.format("• %s (Line %d)",
                issue.getCategory().getTitle(),
                issue.getLineNumber()));
        categoryLabel.setFont(categoryLabel.getFont().deriveFont(Font.BOLD));
        infoPanel.add(categoryLabel, gbc);

        // Descripción
        gbc.gridy = 1;
        JLabel descLabel = new JLabel("<html><body style='width: 600px'>" +
                issue.getDescription() + "</body></html>");
        descLabel.setForeground(UIUtil.getLabelDisabledForeground());
        infoPanel.add(descLabel, gbc);

        // Confidence
        gbc.gridy = 2;
        JLabel confidenceLabel = new JLabel(String.format("Confidence: %.0f%%",
                issue.getConfidence() * 100));
        confidenceLabel.setFont(confidenceLabel.getFont().deriveFont(Font.ITALIC));
        confidenceLabel.setForeground(UIUtil.getLabelDisabledForeground());
        infoPanel.add(confidenceLabel, gbc);

        // Recomendación
        gbc.gridy = 3;
        JLabel recommendLabel = new JLabel("<html><body style='width: 600px'><b>Fix:</b> " +
                issue.getRecommendation() + "</body></html>");
        recommendLabel.setForeground(new JBColor(new Color(0, 100, 0), new Color(98, 150, 85)));
        infoPanel.add(recommendLabel, gbc);

        panel.add(infoPanel, BorderLayout.CENTER);

        // Borde con color según severidad
        panel.setBorder(new CompoundBorder(
                new MatteBorder(0, 3, 0, 0, issue.getSeverity().getColor()),
                new EmptyBorder(5, 10, 5, 10)
        ));

        return panel;
    }

    private JPanel createNoIssuesPanel() {
        JPanel panel = new JPanel(new GridBagLayout());

        JLabel iconLabel = new JLabel("✓");
        iconLabel.setFont(iconLabel.getFont().deriveFont(48f));
        iconLabel.setForeground(JBColor.GREEN.darker());

        JLabel messageLabel = new JLabel("No security vulnerabilities detected!");
        messageLabel.setFont(messageLabel.getFont().deriveFont(Font.BOLD, 16f));

        JLabel subMessageLabel = new JLabel("Your code appears to be secure based on our analysis.");
        subMessageLabel.setForeground(UIUtil.getLabelDisabledForeground());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = JBUI.insets(10);
        panel.add(iconLabel, gbc);

        gbc.gridy = 1;
        panel.add(messageLabel, gbc);

        gbc.gridy = 2;
        panel.add(subMessageLabel, gbc);

        return panel;
    }

    private JPanel createSummaryPanel() {
        JPanel summary = new JPanel(new FlowLayout(FlowLayout.CENTER, 20, 10));
        summary.setBorder(new CompoundBorder(
                new MatteBorder(1, 0, 0, 0, UIUtil.getFocusedBorderColor()),
                new EmptyBorder(10, 10, 10, 10)
        ));

        if (!issues.isEmpty()) {
            // Conteo por severidad
            Map<Severity, Long> counts = issues.stream()
                    .collect(Collectors.groupingBy(SecurityIssue::getSeverity, Collectors.counting()));

            summary.add(new JLabel("Summary:"));

            if (counts.containsKey(Severity.CRITICAL)) {
                JLabel critical = new JLabel(getSeverityIcon(Severity.CRITICAL) +
                        " Critical: " + counts.get(Severity.CRITICAL));
                critical.setForeground(Severity.CRITICAL.getColor());
                summary.add(critical);
            }

            if (counts.containsKey(Severity.HIGH)) {
                JLabel high = new JLabel(getSeverityIcon(Severity.HIGH) +
                        " High: " + counts.get(Severity.HIGH));
                high.setForeground(Severity.HIGH.getColor());
                summary.add(high);
            }

            if (counts.containsKey(Severity.MEDIUM)) {
                JLabel medium = new JLabel(getSeverityIcon(Severity.MEDIUM) +
                        " Medium: " + counts.get(Severity.MEDIUM));
                medium.setForeground(Severity.MEDIUM.getColor());
                summary.add(medium);
            }

            if (counts.containsKey(Severity.LOW)) {
                JLabel low = new JLabel(getSeverityIcon(Severity.LOW) +
                        " Low: " + counts.get(Severity.LOW));
                low.setForeground(Severity.LOW.getColor());
                summary.add(low);
            }
        }

        return summary;
    }

    private String getSeverityIcon(Severity severity) {
        switch (severity) {
            case CRITICAL:
                return "🔴";
            case HIGH:
                return "🟠";
            case MEDIUM:
                return "🟡";
            case LOW:
                return "🔵";
            case INFO:
                return "ℹ️";
            default:
                return "•";
        }
    }

    @Override
    protected Action[] createActions() {
        // Solo botón OK
        return new Action[]{getOKAction()};
    }
}