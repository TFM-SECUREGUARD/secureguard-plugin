package com.secureguard.inspections;

import com.intellij.codeHighlighting.HighlightDisplayLevel;
import com.intellij.codeInspection.*;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.psi.*;
import com.secureguard.analysis.FeatureExtractor;
import com.secureguard.analysis.ModelService;
import com.secureguard.analysis.SeverityCalculator;
import com.secureguard.model.OWASPCategory;
import com.secureguard.model.Severity;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Inspección en tiempo real para detectar vulnerabilidades OWASP mientras se escribe código
 */
public class SecurityInspection extends AbstractBaseJavaLocalInspectionTool {
    private static final Logger LOG = Logger.getInstance(SecurityInspection.class);

    private final FeatureExtractor featureExtractor = new FeatureExtractor();
    private final ModelService modelService = ModelService.getInstance();

    @Override
    @NotNull
    public String getDisplayName() {
        return "SecureGuard Security Analysis";
    }

    @Override
    @NotNull
    public String getGroupDisplayName() {
        return "Security";
    }

    @Override
    @NotNull
    public String getShortName() {
        return "SecureGuardInspection";
    }

    @Override
    public boolean isEnabledByDefault() {
        return true;
    }

    @Override
    @NotNull
    public HighlightDisplayLevel getDefaultLevel() {
        return HighlightDisplayLevel.WARNING;
    }

    /**
     * Visitor para analizar elementos Java
     */
    @NotNull
    @Override
    public PsiElementVisitor buildVisitor(@NotNull ProblemsHolder holder, boolean isOnTheFly) {
        return new JavaElementVisitor() {
            @Override
            public void visitMethod(PsiMethod method) {
                super.visitMethod(method);
                analyzeMethod(method, holder, isOnTheFly);
            }

            @Override
            public void visitClass(PsiClass aClass) {
                super.visitClass(aClass);
                analyzeClass(aClass, holder, isOnTheFly);
            }
        };
    }

    /**
     * Analiza un método en busca de vulnerabilidades
     */
    private void analyzeMethod(@NotNull PsiMethod method,
                               @NotNull ProblemsHolder holder,
                               boolean isOnTheFly) {
        if (!shouldAnalyzeMethod(method)) {
            return;
        }

        try {
            // Extraer features del método
            Map<String, Double> features = featureExtractor.extractFeatures(method);

            // Predecir con el modelo
            Optional<ModelService.PredictionResult> resultOpt = modelService.predict(features);

            if (resultOpt.isPresent()) {
                ModelService.PredictionResult result = resultOpt.get();

                if (result.isVulnerable()) {
                    // Calcular severidad
                    Severity severity = SeverityCalculator.calculateSeverity(
                            result.getCategory(),
                            result.getConfidence(),
                            features
                    );

                    // Registrar el problema
                    registerProblem(method, holder, result, severity, features, isOnTheFly);
                }
            }
        } catch (Exception e) {
            LOG.debug("Error analyzing method: " + method.getName(), e);
        }
    }

    /**
     * Analiza una clase en busca de vulnerabilidades
     */
    private void analyzeClass(@NotNull PsiClass aClass,
                              @NotNull ProblemsHolder holder,
                              boolean isOnTheFly) {
        if (!shouldAnalyzeClass(aClass)) {
            return;
        }

        try {
            // Analizar la clase completa
            Map<String, Double> features = featureExtractor.extractFeatures(aClass);
            Optional<ModelService.PredictionResult> resultOpt = modelService.predict(features);

            if (resultOpt.isPresent()) {
                ModelService.PredictionResult result = resultOpt.get();

                if (result.isVulnerable()) {
                    Severity severity = SeverityCalculator.calculateSeverity(
                            result.getCategory(),
                            result.getConfidence(),
                            features
                    );

                    registerProblem(aClass, holder, result, severity, features, isOnTheFly);
                }
            }
        } catch (Exception e) {
            LOG.debug("Error analyzing class: " + aClass.getName(), e);
        }
    }

    /**
     * Determina si un método debe ser analizado
     */
    private boolean shouldAnalyzeMethod(PsiMethod method) {
        // No analizar métodos vacíos o muy pequeños
        String text = method.getText();
        if (text == null || text.length() < 50) {
            return false;
        }

        // No analizar getters/setters simples
        String name = method.getName();
        if ((name.startsWith("get") || name.startsWith("set") || name.startsWith("is"))
                && method.getBody() != null
                && method.getBody().getStatements().length <= 1) {
            return false;
        }

        // No analizar métodos generados
        PsiModifierList modifierList = method.getModifierList();
        for (PsiAnnotation annotation : modifierList.getAnnotations()) {
            String qualifiedName = annotation.getQualifiedName();
            if (qualifiedName != null &&
                    (qualifiedName.contains("Generated") ||
                            qualifiedName.contains("lombok"))) {
                return false;
            }
        }

        return true;
    }

    /**
     * Determina si una clase debe ser analizada
     */
    private boolean shouldAnalyzeClass(PsiClass aClass) {
        // No analizar interfaces o anotaciones
        if (aClass.isInterface() || aClass.isAnnotationType()) {
            return false;
        }

        // No analizar clases muy pequeñas
        String text = aClass.getText();
        if (text == null || text.length() < 100) {
            return false;
        }

        // No analizar clases de test
        String name = aClass.getName();
        if (name != null && (name.endsWith("Test") || name.endsWith("Tests"))) {
            return false;
        }

        return true;
    }

    /**
     * Registra un problema encontrado
     */
    private void registerProblem(PsiElement element,
                                 ProblemsHolder holder,
                                 ModelService.PredictionResult result,
                                 Severity severity,
                                 Map<String, Double> features,
                                 boolean isOnTheFly) {
        // Determinar el elemento a marcar
        PsiElement elementToHighlight = getElementToHighlight(element);
        if (elementToHighlight == null) {
            return;
        }

        // Crear mensaje descriptivo enriquecido
        String message = createEnhancedProblemMessage(result.getCategory(), element,
                result.getConfidence(), severity);

        // Determinar el nivel de highlight
        ProblemHighlightType highlightType = getHighlightType(severity);

        // Crear quick fixes
        LocalQuickFix[] fixes = createQuickFixes(result.getCategory(), element);

        // Registrar el problema
        holder.registerProblem(elementToHighlight, message, highlightType, fixes);
    }

    /**
     * Determina qué elemento específico resaltar
     */
    @Nullable
    private PsiElement getElementToHighlight(PsiElement element) {
        if (element instanceof PsiMethod) {
            PsiMethod method = (PsiMethod) element;
            // Resaltar el nombre del método
            return method.getNameIdentifier();
        } else if (element instanceof PsiClass) {
            PsiClass aClass = (PsiClass) element;
            // Resaltar el nombre de la clase
            return aClass.getNameIdentifier();
        }
        return element;
    }

    /**
     * Crea el mensaje del problema mejorado con HTML
     */
    private String createEnhancedProblemMessage(OWASPCategory category, PsiElement element,
                                                double confidence, Severity severity) {
        String elementType = element instanceof PsiMethod ? "method" : "class";
        String elementName = element instanceof PsiNamedElement ?
                ((PsiNamedElement) element).getName() : "element";

        // Obtener color según severidad
        String severityColor = getSeverityHtmlColor(severity);

        // Crear mensaje HTML enriquecido
        return String.format(
                "<html>" +
                        "<b style='color: %s'>%s SECURITY ISSUE</b><br/>" +
                        "<b>Category:</b> %s - %s<br/>" +
                        "<b>Location:</b> %s '%s'<br/>" +
                        "<b>Confidence:</b> %.0f%%<br/>" +
                        "<br/>" +
                        "<i>%s</i><br/>" +
                        "<br/>" +
                        "<b>Quick Fix:</b> Press Alt+Enter for suggestions" +
                        "</html>",
                severityColor,
                severity.getDisplayName().toUpperCase(),
                category.getCode(),
                category.getTitle(),
                elementType,
                elementName,
                confidence * 100,
                category.getDescription()
        );
    }

    /**
     * Obtiene el color HTML para la severidad
     */
    private String getSeverityHtmlColor(Severity severity) {
        switch (severity) {
            case CRITICAL:
                return "#FF0000"; // Rojo
            case HIGH:
                return "#FF8C00"; // Naranja oscuro
            case MEDIUM:
                return "#FFD700"; // Dorado
            case LOW:
                return "#1E90FF"; // Azul
            case INFO:
                return "#808080"; // Gris
            default:
                return "#000000"; // Negro
        }
    }

    /**
     * Determina el tipo de highlight según la severidad
     */
    private ProblemHighlightType getHighlightType(Severity severity) {
        switch (severity) {
            case CRITICAL:
                return ProblemHighlightType.ERROR;
            case HIGH:
                return ProblemHighlightType.GENERIC_ERROR_OR_WARNING;
            case MEDIUM:
                return ProblemHighlightType.WARNING;
            case LOW:
                return ProblemHighlightType.WEAK_WARNING;
            case INFO:
                return ProblemHighlightType.INFORMATION;
            default:
                return ProblemHighlightType.WEAK_WARNING;
        }
    }

    /**
     * Crea quick fixes según la categoría de vulnerabilidad
     */
    private LocalQuickFix[] createQuickFixes(OWASPCategory category, PsiElement element) {
        List<LocalQuickFix> fixes = new ArrayList<>();

        // Quick fix genérico para ver detalles - usar el constructor con parámetro
        fixes.add(new ShowVulnerabilityDetailsQuickFix(category));

        // Quick fixes específicos por categoría - usar constructores sin parámetros
        switch (category) {
            case A03_INJECTION:
                if (element instanceof PsiMethod) {
                    fixes.add(new SQLInjectionQuickFix());
                }
                break;

            case A02_CRYPTOGRAPHIC_FAILURES:
                fixes.add(new WeakCryptoQuickFix());
                break;

            case A10_SSRF:
                fixes.add(new SSRFValidationQuickFix());
                break;

            case A05_SECURITY_MISCONFIGURATION:
                fixes.add(new SecurityConfigQuickFix());
                break;

            case A07_AUTHENTICATION_FAILURES:
                fixes.add(new AuthenticationQuickFix());
                break;

            case A01_BROKEN_ACCESS_CONTROL:
                fixes.add(new AccessControlQuickFix());
                break;

            // Agregar más quick fixes según sea necesario
        }

        return fixes.toArray(new LocalQuickFix[0]);
    }
}