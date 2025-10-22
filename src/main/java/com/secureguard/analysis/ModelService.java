package com.secureguard.analysis;

import ai.onnxruntime.*;
import com.intellij.openapi.diagnostic.Logger;
import com.secureguard.model.OWASPCategory;
import org.jetbrains.annotations.NotNull;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.reflect.Type;
import java.nio.FloatBuffer;
import java.util.*;



/**
 * Versión Híbrida Mejorada del ModelService
 * - Usa ONNX para detección binaria (vulnerable/seguro) con alta precisión
 * - Usa reglas mejoradas con análisis de contexto para categorización
 * - Reduce falsos positivos analizando patrones seguros
 */
public class ModelService {
    private static final Logger LOG = Logger.getInstance(ModelService.class);
    private static final String MODEL_PATH = "/models/secureguard_model.onnx";
    private static final String FEATURE_MAPPING_PATH = "/models/feature_mapping.json";
    private static final String NORMALIZATION_STATS_PATH = "/models/normalization_stats.json";

    private static ModelService instance;
    private OrtSession session;
    private OrtEnvironment env;
    private List<String> featureNames;
    private Map<String, Integer> featureIndices;
    private Map<String, Double> featureMeans;
    private Map<String, Double> featureScales;
    private boolean onnxAvailable = false;

    private ModelService() {
        initialize();
    }

    public static synchronized ModelService getInstance() {
        if (instance == null) {
            instance = new ModelService();
        }
        return instance;
    }

    private void initialize() {
        try {
            LOG.info("Initializing Hybrid ModelService...");

            // Intentar cargar ONNX
            try {
                initializeONNX();
                onnxAvailable = true;
                LOG.info("ONNX Runtime initialized successfully - using hybrid mode");
            } catch (Exception e) {
                LOG.warn("ONNX Runtime not available, using pure rule-based detection", e);
                onnxAvailable = false;
            }

        } catch (Exception e) {
            LOG.error("Failed to initialize model service", e);
        }
    }

    private void initializeONNX() throws Exception {
        env = OrtEnvironment.getEnvironment();

        try (InputStream modelStream = getClass().getResourceAsStream(MODEL_PATH)) {
            if (modelStream == null) {
                throw new RuntimeException("Model file not found: " + MODEL_PATH);
            }

            byte[] modelBytes = modelStream.readAllBytes();
            session = env.createSession(modelBytes, new OrtSession.SessionOptions());
            LOG.info("ONNX model loaded successfully");
        }

        loadFeatureMapping();
        loadNormalizationStats();
    }

    private void loadFeatureMapping() throws Exception {
        try (InputStream stream = getClass().getResourceAsStream(FEATURE_MAPPING_PATH);
             Reader reader = new InputStreamReader(stream)) {

            Gson gson = new Gson();
            Type type = new TypeToken<Map<String, Object>>(){}.getType();
            Map<String, Object> mapping = gson.fromJson(reader, type);

            featureNames = (List<String>) mapping.get("feature_names");
            Map<String, Number> indices = (Map<String, Number>) mapping.get("feature_indices");
            featureIndices = new HashMap<>();
            for (Map.Entry<String, Number> entry : indices.entrySet()) {
                featureIndices.put(entry.getKey(), entry.getValue().intValue());
            }
        }
    }

    private void loadNormalizationStats() throws Exception {
        try (InputStream stream = getClass().getResourceAsStream(NORMALIZATION_STATS_PATH);
             Reader reader = new InputStreamReader(stream)) {

            Gson gson = new Gson();
            Type type = new TypeToken<Map<String, Object>>(){}.getType();
            Map<String, Object> stats = gson.fromJson(reader, type);

            List<Number> means = (List<Number>) stats.get("means");
            List<Number> scales = (List<Number>) stats.get("scales");

            featureMeans = new HashMap<>();
            featureScales = new HashMap<>();

            for (int i = 0; i < featureNames.size(); i++) {
                String featureName = featureNames.get(i);
                featureMeans.put(featureName, means.get(i).doubleValue());
                featureScales.put(featureName, scales.get(i).doubleValue());
            }
        }
    }

    /**
     * Predicción híbrida mejorada con análisis de contexto
     */
    public Optional<PredictionResult> predict(@NotNull Map<String, Double> features) {
        try {
            // PRIMERO: Verificar si es código claramente SEGURO
            if (isDefinitelySecureCode(features)) {
                LOG.info("Code identified as secure by pattern analysis");
                return Optional.of(new PredictionResult(false, 0.1, OWASPCategory.NONE));
            }

            // SEGUNDO: Detección de vulnerabilidades
            boolean isVulnerable;
            double baseConfidence;

            if (onnxAvailable) {
                Optional<BinaryPrediction> binaryResult = predictWithONNX(features);
                if (binaryResult.isPresent()) {
                    isVulnerable = binaryResult.get().isVulnerable;
                    baseConfidence = binaryResult.get().confidence;
                    LOG.info(String.format("ONNX prediction: %s (confidence: %.2f%%)",
                            isVulnerable ? "VULNERABLE" : "SAFE", baseConfidence * 100));
                } else {
                    return predictWithRules(features);
                }
            } else {
                BinaryPrediction ruleBased = detectVulnerabilityWithRules(features);
                isVulnerable = ruleBased.isVulnerable;
                baseConfidence = ruleBased.confidence;
            }

            if (!isVulnerable) {
                return Optional.of(new PredictionResult(false, baseConfidence, OWASPCategory.NONE));
            }

            // TERCERO: Categorización OWASP mejorada
            OWASPCategory category = categorizeVulnerability(features);

            // Ajustar confianza basándose en la fortaleza de los indicadores
            double categoryConfidence = calculateCategoryConfidence(features, category);
            double finalConfidence = (baseConfidence * 0.7) + (categoryConfidence * 0.3);

            LOG.info(String.format("Final prediction: %s with confidence %.2f%%",
                    category.getCode(), finalConfidence * 100));

            return Optional.of(new PredictionResult(true, finalConfidence, category));

        } catch (Exception e) {
            LOG.error("Prediction failed", e);
            return Optional.empty();
        }
    }

    /**
     * Identifica patrones de código definitivamente SEGURO
     */
    private boolean isDefinitelySecureCode(Map<String, Double> features) {
        // Verificar si es un método auxiliar simple (como bytesToHex)
        double codeLength = features.getOrDefault("code_length", 0.0);
        double numLines = features.getOrDefault("num_lines", 0.0);
        double complexity = features.getOrDefault("cyclomatic_complexity", 0.0);
        double hasUserInput = features.getOrDefault("has_user_input", 0.0);
        double dangerousMethods = features.getOrDefault("dangerous_methods_count", 0.0);

        // Método auxiliar simple sin entrada de usuario
        if (codeLength < 300 && numLines < 15 && complexity <= 3 &&
                hasUserInput == 0 && dangerousMethods == 0) {
            LOG.debug("Identified as simple utility method");
            return true;
        }

        // Verificar uso de PreparedStatement (seguro contra SQL injection)
        double injectionKeywords = features.getOrDefault("injection_keywords", 0.0);
        double injectionMethods = features.getOrDefault("injection_methods", 0.0);

        // Si tiene palabras SQL pero usa PreparedStatement, es SEGURO
        if (injectionKeywords > 0 && features.getOrDefault("injection_patterns", 0.0) == 0) {
            // Buscar indicadores de PreparedStatement
            // En un análisis más sofisticado, verificaríamos el AST
            LOG.debug("SQL operations detected but appears to use safe patterns");
            return false; // Por ahora, dejar que el análisis completo decida
        }

        return false;
    }

    /**
     * Predicción binaria usando ONNX
     */
    private Optional<BinaryPrediction> predictWithONNX(Map<String, Double> features) {
        try {
            float[] inputArray = prepareFeatures(features);

            long[] shape = {1, featureNames.size()};
            OnnxTensor inputTensor = OnnxTensor.createTensor(env, FloatBuffer.wrap(inputArray), shape);

            Map<String, OnnxTensor> inputs = Collections.singletonMap("float_input", inputTensor);
            try (OrtSession.Result result = session.run(inputs)) {

                OnnxTensor output = (OnnxTensor) result.get(0);
                Object outputValue = output.getValue();

                float confidence;
                boolean isVulnerable;

                if (outputValue instanceof float[][]) {
                    float[][] probabilities = (float[][]) outputValue;
                    confidence = probabilities[0][1];
                    isVulnerable = confidence > 0.5f;
                } else if (outputValue instanceof long[]) {
                    long[] prediction = (long[]) outputValue;
                    isVulnerable = prediction[0] == 1;
                    confidence = isVulnerable ? 0.85f : 0.15f;
                } else if (outputValue instanceof long[][]) {
                    long[][] prediction = (long[][]) outputValue;
                    isVulnerable = prediction[0][0] == 1;
                    confidence = isVulnerable ? 0.85f : 0.15f;
                } else {
                    LOG.error("Unexpected output type: " + outputValue.getClass().getName());
                    return Optional.empty();
                }

                return Optional.of(new BinaryPrediction(isVulnerable, confidence));
            }

        } catch (Exception e) {
            LOG.error("ONNX prediction failed", e);
            return Optional.empty();
        }
    }

    /**
     * Detección binaria con reglas mejoradas
     */
    private BinaryPrediction detectVulnerabilityWithRules(Map<String, Double> features) {
        double maxScore = 0.0;

        // Verificar indicadores de cada categoría con umbrales más estrictos
        maxScore = Math.max(maxScore, scoreInjection(features));
        maxScore = Math.max(maxScore, scoreSSRF(features));
        maxScore = Math.max(maxScore, scoreCrypto(features));
        maxScore = Math.max(maxScore, scoreAccessControl(features));
        maxScore = Math.max(maxScore, scoreAuth(features));
        maxScore = Math.max(maxScore, scoreConfig(features));
        maxScore = Math.max(maxScore, scoreIntegrity(features));
        maxScore = Math.max(maxScore, scoreDesign(features));

        // Umbral más alto para reducir falsos positivos
        boolean isVulnerable = maxScore > 0.5;
        return new BinaryPrediction(isVulnerable, isVulnerable ? maxScore : 0.2);
    }

    /**
     * Categorización mejorada con análisis de contexto
     */
    private OWASPCategory categorizeVulnerability(Map<String, Double> features) {
        Map<OWASPCategory, Double> scores = new HashMap<>();

        // Calcular scores con lógica mejorada
        scores.put(OWASPCategory.A03_INJECTION, scoreInjection(features));
        scores.put(OWASPCategory.A10_SSRF, scoreSSRF(features));
        scores.put(OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES, scoreCrypto(features));
        scores.put(OWASPCategory.A01_BROKEN_ACCESS_CONTROL, scoreAccessControl(features));
        scores.put(OWASPCategory.A07_AUTHENTICATION_FAILURES, scoreAuth(features));
        scores.put(OWASPCategory.A05_SECURITY_MISCONFIGURATION, scoreConfig(features));
        scores.put(OWASPCategory.A08_SOFTWARE_INTEGRITY_FAILURES, scoreIntegrity(features));
        scores.put(OWASPCategory.A04_INSECURE_DESIGN, scoreDesign(features));
        scores.put(OWASPCategory.A09_LOGGING_MONITORING_FAILURES, scoreLogging(features));
        scores.put(OWASPCategory.A06_VULNERABLE_COMPONENTS, scoreComponents(features));

        // Log para debugging
        if (LOG.isDebugEnabled()) {
            LOG.debug("Category scores:");
            scores.entrySet().stream()
                    .filter(e -> e.getValue() > 0)
                    .forEach(e -> LOG.debug(String.format("  %s: %.2f", e.getKey().getCode(), e.getValue())));
        }

        // Encontrar la categoría con mayor score
        OWASPCategory bestCategory = scores.entrySet().stream()
                .filter(e -> e.getValue() > 0)
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse(OWASPCategory.A04_INSECURE_DESIGN);

        LOG.info("Selected category: " + bestCategory.getCode() + " with score: " + scores.get(bestCategory));

        return bestCategory;
    }

    // Métodos de scoring mejorados

    private double scoreInjection(Map<String, Double> features) {
        double injectionScore = features.getOrDefault("injection_score", 0.0);
        double injectionKeywords = features.getOrDefault("injection_keywords", 0.0);
        double injectionMethods = features.getOrDefault("injection_methods", 0.0);
        double hasUserInput = features.getOrDefault("has_user_input", 0.0);
        double stringConcat = features.getOrDefault("string_concatenation_count", 0.0);

        // NO es vulnerable si usa PreparedStatement
        if (injectionKeywords > 0 && injectionMethods == 0 && stringConcat == 0) {
            return 0.0; // Probablemente usa PreparedStatement
        }

        // ES vulnerable si hay concatenación + SQL + input
        if (injectionKeywords > 0 && hasUserInput > 0 && stringConcat > 0) {
            double score = 0.8;
            if (injectionScore > 0.5) score += 0.15;
            return Math.min(score, 0.95);
        }

        return 0.0;
    }

    private double scoreSSRF(Map<String, Double> features) {
        double ssrfScore = features.getOrDefault("ssrf_score", 0.0);
        double ssrfKeywords = features.getOrDefault("ssrf_keywords", 0.0);
        double ssrfMethods = features.getOrDefault("ssrf_methods", 0.0);
        double hasUserInput = features.getOrDefault("pattern_user_input", 0.0);
        double networkOps = features.getOrDefault("pattern_network_operations", 0.0);

        if (ssrfKeywords > 0 && (hasUserInput > 0 || features.getOrDefault("has_user_input", 0.0) > 0)) {
            double score = 0.7;
            if (ssrfScore > 0.5) score += 0.2;
            if (ssrfMethods > 0) score += 0.05;
            return Math.min(score, 0.95);
        }

        return 0.0;
    }

    private double scoreCrypto(Map<String, Double> features) {
        double cryptoScore = features.getOrDefault("crypto_score", 0.0);
        double cryptoMethods = features.getOrDefault("crypto_methods", 0.0);

        // Solo marcar como vulnerable si realmente usa algoritmos débiles
        if (cryptoMethods > 0 && cryptoScore > 0.3) {
            return Math.min(0.7 + (cryptoScore * 0.3), 0.90);
        }

        return 0.0;
    }

    private double scoreAccessControl(Map<String, Double> features) {
        double hasFileOps = features.getOrDefault("has_file_ops", 0.0);
        double hasUserInput = features.getOrDefault("has_user_input", 0.0);
        double patternUserInput = features.getOrDefault("pattern_user_input", 0.0);

        // Path traversal: archivo + input usuario
        if (hasFileOps > 0 && (hasUserInput > 0 || patternUserInput > 0)) {
            return 0.85;
        }

        return 0.0;
    }

    private double scoreAuth(Map<String, Double> features) {
        double authScore = features.getOrDefault("auth_score", 0.0);
        double authPatterns = features.getOrDefault("auth_patterns", 0.0);

        // Detectar contraseñas hardcodeadas o sesiones mal manejadas
        if (authPatterns > 2 && authScore > 0.5) {
            return Math.min(0.7 + (authScore * 0.3), 0.9);
        }

        return 0.0;
    }

    private double scoreConfig(Map<String, Double> features) {
        double configScore = features.getOrDefault("config_score", 0.0);
        double configPatterns = features.getOrDefault("config_patterns", 0.0);
        double configMethods = features.getOrDefault("config_methods", 0.0);

        // Solo si hay patrones claros de mala configuración
        if (configPatterns > 1 || configMethods > 1) {
            return Math.min(0.6 + (configScore * 0.3), 0.85);
        }

        return 0.0;
    }

    private double scoreIntegrity(Map<String, Double> features) {
        double dangerousMethods = features.getOrDefault("dangerous_methods_count", 0.0);
        double hasUserInput = features.getOrDefault("has_user_input", 0.0);
        double suspiciousImports = features.getOrDefault("suspicious_imports_count", 0.0);

        // Deserialización insegura
        if (dangerousMethods > 0 && (hasUserInput > 0 || suspiciousImports > 0)) {
            return Math.min(0.7 + (dangerousMethods * 0.1), 0.9);
        }

        return 0.0;
    }

    private double scoreDesign(Map<String, Double> features) {
        double complexity = features.getOrDefault("cyclomatic_complexity", 0.0);
        double nesting = features.getOrDefault("max_nesting_depth", 0.0);
        double numMethods = features.getOrDefault("num_methods", 0.0);

        // Complejidad muy alta = problema de diseño
        if (complexity > 20) {
            double score = 0.6;
            if (complexity > 30) score += 0.2;
            if (nesting > 7) score += 0.1;
            return Math.min(score, 0.9);
        }

        return 0.0;
    }

    private double scoreLogging(Map<String, Double> features) {
        double loggingKeywords = features.getOrDefault("logging_keywords", 0.0);
        double loggingScore = features.getOrDefault("logging_score", 0.0);

        // Solo si falta logging en operaciones críticas
        if (loggingKeywords == 0 && features.getOrDefault("has_user_input", 0.0) > 0) {
            return 0.5;
        }

        return 0.0;
    }

    private double scoreComponents(Map<String, Double> features) {
        double componentsKeywords = features.getOrDefault("components_keywords", 0.0);
        double suspiciousImports = features.getOrDefault("suspicious_imports_count", 0.0);

        // Solo si hay evidencia fuerte de librerías vulnerables
        if (componentsKeywords > 2 || suspiciousImports > 3) {
            return Math.min(0.6 + (componentsKeywords * 0.1), 0.8);
        }

        return 0.0;
    }

    private double calculateCategoryConfidence(Map<String, Double> features, OWASPCategory category) {
        switch (category) {
            case A03_INJECTION:
                return scoreInjection(features);
            case A10_SSRF:
                return scoreSSRF(features);
            case A02_CRYPTOGRAPHIC_FAILURES:
                return scoreCrypto(features);
            case A01_BROKEN_ACCESS_CONTROL:
                return scoreAccessControl(features);
            case A07_AUTHENTICATION_FAILURES:
                return scoreAuth(features);
            case A05_SECURITY_MISCONFIGURATION:
                return scoreConfig(features);
            case A08_SOFTWARE_INTEGRITY_FAILURES:
                return scoreIntegrity(features);
            case A04_INSECURE_DESIGN:
                return scoreDesign(features);
            case A09_LOGGING_MONITORING_FAILURES:
                return scoreLogging(features);
            case A06_VULNERABLE_COMPONENTS:
                return scoreComponents(features);
            default:
                return 0.5;
        }
    }

    private float[] prepareFeatures(Map<String, Double> features) {
        float[] normalized = new float[featureNames.size()];

        for (int i = 0; i < featureNames.size(); i++) {
            String featureName = featureNames.get(i);
            Double value = features.getOrDefault(featureName, 0.0);

            double mean = featureMeans.get(featureName);
            double scale = featureScales.get(featureName);

            if (scale > 0) {
                normalized[i] = (float) ((value - mean) / scale);
            } else {
                normalized[i] = 0.0f;
            }
        }

        return normalized;
    }

    private Optional<PredictionResult> predictWithRules(Map<String, Double> features) {
        BinaryPrediction binary = detectVulnerabilityWithRules(features);

        if (!binary.isVulnerable) {
            return Optional.of(new PredictionResult(false, binary.confidence, OWASPCategory.NONE));
        }

        OWASPCategory category = categorizeVulnerability(features);
        double categoryConfidence = calculateCategoryConfidence(features, category);

        return Optional.of(new PredictionResult(true, categoryConfidence, category));
    }

    public void close() {
        try {
            if (session != null) {
                session.close();
            }
            if (env != null) {
                env.close();
            }
        } catch (Exception e) {
            LOG.error("Error closing model service", e);
        }
    }

    private static class BinaryPrediction {
        final boolean isVulnerable;
        final double confidence;

        BinaryPrediction(boolean isVulnerable, double confidence) {
            this.isVulnerable = isVulnerable;
            this.confidence = confidence;
        }
    }

    public static class PredictionResult {
        private final boolean isVulnerable;
        private final double confidence;
        private final OWASPCategory category;

        public PredictionResult(boolean isVulnerable, double confidence, OWASPCategory category) {
            this.isVulnerable = isVulnerable;
            this.confidence = confidence;
            this.category = category;
        }

        public boolean isVulnerable() {
            return isVulnerable;
        }

        public double getConfidence() {
            return confidence;
        }

        public OWASPCategory getCategory() {
            return category;
        }

        @Override
        public String toString() {
            return String.format("PredictionResult{vulnerable=%s, confidence=%.2f%%, category=%s}",
                    isVulnerable, confidence * 100, category.getCode());
        }
    }
}