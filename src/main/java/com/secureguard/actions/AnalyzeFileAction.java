package com.secureguard.actions;

import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.CommonDataKeys;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.progress.ProgressIndicator;
import com.intellij.openapi.progress.ProgressManager;
import com.intellij.openapi.progress.Task;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.Messages;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.psi.*;
import com.intellij.psi.util.PsiTreeUtil;
import com.secureguard.analysis.FeatureExtractor;
import com.secureguard.analysis.ModelService;
import com.secureguard.analysis.SeverityCalculator;
import com.secureguard.model.OWASPCategory;
import com.secureguard.model.SecurityIssue;
import com.secureguard.model.Severity;
import org.jetbrains.annotations.NotNull;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import com.intellij.openapi.util.Computable;

/**
 * Acción para analizar el archivo actual en busca de vulnerabilidades
 */
public class AnalyzeFileAction extends AnAction {
    private static final Logger LOG = Logger.getInstance(AnalyzeFileAction.class);

    @Override
    public void actionPerformed(@NotNull AnActionEvent e) {
        Project project = e.getProject();
        if (project == null) return;

        VirtualFile file = e.getData(CommonDataKeys.VIRTUAL_FILE);
        if (file == null || !file.getName().endsWith(".java")) {
            Messages.showWarningDialog(project,
                    "Please select a Java file to analyze",
                    "SecureGuard");
            return;
        }

        LOG.info("Starting SecureGuard analysis for file: " + file.getName());

        // Ejecutar análisis en background
        ProgressManager.getInstance().run(new Task.Backgroundable(project, "Analyzing Security Vulnerabilities", true) {
            @Override
            public void run(@NotNull ProgressIndicator indicator) {
                try {
                    indicator.setText("Initializing SecureGuard analysis...");

                    // Obtener el PSI file dentro de un read action
                    AtomicReference<PsiJavaFile> javaFileRef = new AtomicReference<>();
                    ApplicationManager.getApplication().runReadAction(() -> {
                        PsiFile psiFile = PsiManager.getInstance(project).findFile(file);
                        if (psiFile instanceof PsiJavaFile) {
                            javaFileRef.set((PsiJavaFile) psiFile);
                        }
                    });

                    PsiJavaFile javaFile = javaFileRef.get();
                    if (javaFile == null) {
                        LOG.warn("File is not a valid Java file: " + file.getName());
                        return;
                    }

                    List<SecurityIssue> issues = new ArrayList<>();

                    // Obtener servicios
                    ModelService modelService = ModelService.getInstance();
                    FeatureExtractor extractor = new FeatureExtractor();

                    // Analizar cada método en el archivo
                    indicator.setText("Analyzing methods...");

                    // Obtener métodos dentro de un read action
                    List<PsiMethod> methods = new ArrayList<>();
                    ApplicationManager.getApplication().runReadAction(() -> {
                        Collection<PsiMethod> foundMethods = PsiTreeUtil.findChildrenOfType(javaFile, PsiMethod.class);
                        methods.addAll(foundMethods);
                    });

                    int total = methods.size();
                    int current = 0;

                    for (PsiMethod method : methods) {
                        if (indicator.isCanceled()) break;

                        current++;
                        String methodName = ApplicationManager.getApplication().runReadAction((Computable<String>) () -> method.getName());
                        indicator.setText2(String.format("Analyzing method %d of %d: %s",
                                current, total, methodName));
                        indicator.setFraction((double) current / total);

                        try {
                            // Extraer features dentro de un read action
                            Map<String, Double> features = ApplicationManager.getApplication().runReadAction(
                                    (Computable<Map<String, Double>>) () -> extractor.extractFeatures(method)
                            );

                            // Log features para debugging
                            LOG.info("Method " + methodName + " features extracted: " + features.size());
                            if (LOG.isDebugEnabled()) {
                                features.forEach((key, value) ->
                                        LOG.debug(String.format("  %s: %.4f", key, value)));
                            }

                            // Predecir con el modelo
                            Optional<ModelService.PredictionResult> resultOpt = modelService.predict(features);

                            if (resultOpt.isPresent()) {
                                ModelService.PredictionResult result = resultOpt.get();
                                LOG.info(String.format("Method %s - Prediction: %s",
                                        methodName, result.toString()));

                                if (result.isVulnerable()) {
                                    // Crear issue dentro de un read action
                                    ApplicationManager.getApplication().runReadAction(() -> {
                                        // Calcular severidad usando la categoría y features
                                        Severity severity = SeverityCalculator.calculateSeverity(
                                                result.getCategory(),
                                                result.getConfidence(),
                                                features
                                        );

                                        SecurityIssue issue = new SecurityIssue(
                                                result.getCategory(),
                                                severity,
                                                generateDescription(result.getCategory(), method),
                                                generateRecommendation(result.getCategory()),
                                                method,
                                                result.getConfidence(),
                                                result.getCategory().getTitle()
                                        );
                                        issues.add(issue);
                                    });
                                }
                            } else {
                                LOG.warn("No prediction result for method: " + methodName);
                            }
                        } catch (Exception ex) {
                            LOG.error("Error analyzing method: " + methodName, ex);
                        }
                    }

                    // Analizar clases también
                    indicator.setText("Analyzing classes...");

                    List<PsiClass> classes = new ArrayList<>();
                    ApplicationManager.getApplication().runReadAction(() -> {
                        classes.addAll(Arrays.asList(javaFile.getClasses()));
                    });

                    for (PsiClass psiClass : classes) {
                        if (indicator.isCanceled()) break;

                        String className = ApplicationManager.getApplication().runReadAction(
                                (Computable<String>) () -> psiClass.getName()
                        );

                        try {
                            // Extraer features dentro de un read action
                            Map<String, Double> features = ApplicationManager.getApplication().runReadAction(
                                    (Computable<Map<String, Double>>) () -> extractor.extractFeatures(psiClass)
                            );

                            LOG.info("Class " + className + " features extracted: " + features.size());

                            Optional<ModelService.PredictionResult> resultOpt = modelService.predict(features);

                            if (resultOpt.isPresent()) {
                                ModelService.PredictionResult result = resultOpt.get();
                                LOG.info(String.format("Class %s - Prediction: %s",
                                        className, result.toString()));

                                if (result.isVulnerable()) {
                                    ApplicationManager.getApplication().runReadAction(() -> {
                                        // Calcular severidad usando la categoría y features
                                        Severity severity = SeverityCalculator.calculateSeverity(
                                                result.getCategory(),
                                                result.getConfidence(),
                                                features
                                        );

                                        SecurityIssue issue = new SecurityIssue(
                                                result.getCategory(),
                                                severity,
                                                generateDescription(result.getCategory(), psiClass),
                                                generateRecommendation(result.getCategory()),
                                                psiClass,
                                                result.getConfidence(),
                                                result.getCategory().getTitle()
                                        );
                                        issues.add(issue);
                                    });
                                }
                            }
                        } catch (Exception ex) {
                            LOG.error("Error analyzing class: " + className, ex);
                        }
                    }

                    // Mostrar resultados en el EDT (Event Dispatch Thread)
                    ApplicationManager.getApplication().invokeLater(() -> {
                        showResults(project, file.getName(), issues);
                    });

                } catch (Exception ex) {
                    LOG.error("Error during security analysis", ex);
                    ApplicationManager.getApplication().invokeLater(() -> {
                        Messages.showErrorDialog(project,
                                "Error analyzing file: " + ex.getMessage(),
                                "SecureGuard Error");
                    });
                }
            }
        });
    }

    @Override
    public void update(@NotNull AnActionEvent e) {
        // Habilitar solo si hay un archivo Java seleccionado
        VirtualFile file = e.getData(CommonDataKeys.VIRTUAL_FILE);
        boolean enabled = file != null && file.getName().endsWith(".java");
        e.getPresentation().setEnabled(enabled);
    }

    private String generateDescription(OWASPCategory category, PsiElement element) {
        String elementName = ApplicationManager.getApplication().runReadAction(
                (Computable<String>) () -> {
                    if (element instanceof PsiNamedElement) {
                        return ((PsiNamedElement) element).getName();
                    }
                    return "code";
                }
        );

        return String.format("Potential %s vulnerability detected in %s. " +
                        "This code pattern matches known vulnerable patterns.",
                category.getTitle(), elementName);
    }

    private String generateRecommendation(OWASPCategory category) {
        switch (category) {
            case A03_INJECTION:
                return "Use parameterized queries or prepared statements. " +
                        "Never concatenate user input directly into queries.";
            case A01_BROKEN_ACCESS_CONTROL:
                return "Implement proper access control checks. " +
                        "Verify user permissions before allowing access to resources.";
            case A02_CRYPTOGRAPHIC_FAILURES:
                return "Use strong encryption algorithms (AES-256). " +
                        "Never use MD5, SHA1, or DES for security purposes.";
            case A10_SSRF:
                return "Validate and sanitize all URL inputs. " +
                        "Implement a whitelist of allowed domains.";
            case A07_AUTHENTICATION_FAILURES:
                return "Never hardcode passwords. Use secure password storage. " +
                        "Implement proper session management.";
            case A05_SECURITY_MISCONFIGURATION:
                return "Avoid exposing stack traces in production. " +
                        "Use proper logging frameworks with appropriate levels.";
            case A08_SOFTWARE_INTEGRITY_FAILURES:
                return "Avoid deserializing untrusted data. " +
                        "Implement integrity checks and input validation.";
            case A09_LOGGING_MONITORING_FAILURES:
                return "Implement comprehensive logging and monitoring. " +
                        "Log security events and failed authentication attempts.";
            case A06_VULNERABLE_COMPONENTS:
                return "Keep all dependencies up to date. " +
                        "Regularly scan for known vulnerabilities in components.";
            case A04_INSECURE_DESIGN:
                return "Simplify complex logic. Reduce cyclomatic complexity. " +
                        "Follow secure design principles.";
            default:
                return "Review this code for security best practices. " +
                        "Consider implementing additional validation and sanitization.";
        }
    }

    private void showResults(Project project, String fileName, List<SecurityIssue> issues) {
        if (issues.isEmpty()) {
            Messages.showInfoMessage(project,
                    String.format("No security vulnerabilities detected in %s\n\n" +
                            "SecureGuard analyzed all methods and classes.", fileName),
                    "SecureGuard - Analysis Complete");
        } else {
            StringBuilder message = new StringBuilder();
            message.append(String.format("Found %d potential vulnerabilities in %s:\n\n",
                    issues.size(), fileName));

            // Agrupar por severidad
            long critical = issues.stream().filter(i -> i.getSeverity() == Severity.CRITICAL).count();
            long high = issues.stream().filter(i -> i.getSeverity() == Severity.HIGH).count();
            long medium = issues.stream().filter(i -> i.getSeverity() == Severity.MEDIUM).count();
            long low = issues.stream().filter(i -> i.getSeverity() == Severity.LOW).count();

            if (critical > 0) message.append(String.format("🔴 Critical: %d\n", critical));
            if (high > 0) message.append(String.format("🟠 High: %d\n", high));
            if (medium > 0) message.append(String.format("🟡 Medium: %d\n", medium));
            if (low > 0) message.append(String.format("🔵 Low: %d\n", low));

            message.append("\nTop issues:\n");
            issues.stream()
                    .limit(5)
                    .forEach(issue -> {
                        message.append(String.format("\n• %s (Line %d)\n  %s\n",
                                issue.getCategory().getTitle(),
                                issue.getLineNumber(),
                                issue.getDescription()));
                    });

            if (issues.size() > 5) {
                message.append(String.format("\n... and %d more issues", issues.size() - 5));
            }

            Messages.showWarningDialog(project, message.toString(), "SecureGuard - Vulnerabilities Found");
        }
    }
}