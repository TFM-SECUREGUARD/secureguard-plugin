package com.secureguard.analysis;

import ai.onnxruntime.*;
import com.intellij.openapi.diagnostic.Logger;
import com.secureguard.model.OWASPCategory;
import org.jetbrains.annotations.NotNull;

import java.io.InputStream;
import java.nio.FloatBuffer;
import java.util.*;
import java.util.stream.Collectors;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.reflect.Type;

/**
 * Servicio para cargar y ejecutar el modelo ONNX de detección de vulnerabilidades
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
    private boolean initialized = false;

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
            LOG.info("Initializing SecureGuard Model Service...");

            // Cargar el environment de ONNX Runtime
            env = OrtEnvironment.getEnvironment();

            // Cargar el modelo
            try (InputStream modelStream = getClass().getResourceAsStream(MODEL_PATH)) {
                if (modelStream == null) {
                    throw new RuntimeException("Model file not found: " + MODEL_PATH);
                }

                byte[] modelBytes = modelStream.readAllBytes();
                session = env.createSession(modelBytes, new OrtSession.SessionOptions());
                LOG.info("Model loaded successfully. Size: " + modelBytes.length + " bytes");
            }

            // Cargar mapping de features
            loadFeatureMapping();

            // Cargar estadísticas de normalización
            loadNormalizationStats();

            // Verificar la estructura del modelo
            verifyModelStructure();

            initialized = true;
            LOG.info("SecureGuard Model Service initialized successfully");

        } catch (Exception e) {
            LOG.error("Failed to initialize model service", e);
            throw new RuntimeException("Model initialization failed", e);
        }
    }

    private void loadFeatureMapping() throws Exception {
        try (InputStream stream = getClass().getResourceAsStream(FEATURE_MAPPING_PATH);
             Reader reader = new InputStreamReader(stream)) {

            Gson gson = new Gson();
            Type type = new TypeToken<Map<String, Object>>(){}.getType();
            Map<String, Object> mapping = gson.fromJson(reader, type);

            // Extraer nombres de features
            featureNames = (List<String>) mapping.get("feature_names");

            // Extraer índices de features
            Map<String, Number> indices = (Map<String, Number>) mapping.get("feature_indices");
            featureIndices = new HashMap<>();
            for (Map.Entry<String, Number> entry : indices.entrySet()) {
                featureIndices.put(entry.getKey(), entry.getValue().intValue());
            }

            LOG.info("Loaded " + featureNames.size() + " feature names");
        }
    }

    private void loadNormalizationStats() throws Exception {
        try (InputStream stream = getClass().getResourceAsStream(NORMALIZATION_STATS_PATH);
             Reader reader = new InputStreamReader(stream)) {

            Gson gson = new Gson();
            Type type = new TypeToken<Map<String, Object>>(){}.getType();
            Map<String, Object> stats = gson.fromJson(reader, type);

            // Extraer means y scales
            List<Number> means = (List<Number>) stats.get("means");
            List<Number> scales = (List<Number>) stats.get("scales");

            featureMeans = new HashMap<>();
            featureScales = new HashMap<>();

            for (int i = 0; i < featureNames.size(); i++) {
                String featureName = featureNames.get(i);
                featureMeans.put(featureName, means.get(i).doubleValue());
                featureScales.put(featureName, scales.get(i).doubleValue());
            }

            LOG.info("Loaded normalization stats for " + featureMeans.size() + " features");
        }
    }

    private void verifyModelStructure() throws OrtException {
        // Verificar inputs
        Map<String, NodeInfo> inputInfo = session.getInputInfo();
        LOG.info("Model inputs:");
        for (Map.Entry<String, NodeInfo> entry : inputInfo.entrySet()) {
            TensorInfo tensorInfo = (TensorInfo) entry.getValue().getInfo();
            LOG.info("  - " + entry.getKey() + ": shape=" + Arrays.toString(tensorInfo.getShape()) +
                    ", type=" + tensorInfo.type);
        }

        // Verificar outputs
        Map<String, NodeInfo> outputInfo = session.getOutputInfo();
        LOG.info("Model outputs:");
        for (Map.Entry<String, NodeInfo> entry : outputInfo.entrySet()) {
            TensorInfo tensorInfo = (TensorInfo) entry.getValue().getInfo();
            LOG.info("  - " + entry.getKey() + ": shape=" + Arrays.toString(tensorInfo.getShape()) +
                    ", type=" + tensorInfo.type);
        }
    }

    /**
     * Realiza una predicción usando el modelo
     * @param features Mapa de features extraídas del código
     * @return Resultado de la predicción
     */
    public Optional<PredictionResult> predict(@NotNull Map<String, Double> features) {
        if (!initialized) {
            LOG.error("Model service not initialized");
            return Optional.empty();
        }

        try {
            // Preparar el array de features en el orden correcto
            float[] inputArray = prepareFeatures(features);

            // Crear tensor de entrada
            long[] shape = {1, featureNames.size()};
            OnnxTensor inputTensor = OnnxTensor.createTensor(env, FloatBuffer.wrap(inputArray), shape);

            // Ejecutar inferencia
            Map<String, OnnxTensor> inputs = Collections.singletonMap("float_input", inputTensor);
            try (OrtSession.Result result = session.run(inputs)) {

                // Obtener el output - puede ser float[][] o long[]
                OnnxTensor output = (OnnxTensor) result.get(0);
                Object outputValue = output.getValue();

                float vulnerableProb;
                boolean isVulnerable;

                // Manejar diferentes tipos de output
                if (outputValue instanceof float[][]) {
                    // Output es probabilidades
                    float[][] probabilities = (float[][]) outputValue;
                    vulnerableProb = probabilities[0][1];
                    isVulnerable = vulnerableProb > 0.5f;
                } else if (outputValue instanceof long[]) {
                    // Output es clase predicha (0 o 1)
                    long[] prediction = (long[]) outputValue;
                    isVulnerable = prediction[0] == 1;
                    vulnerableProb = isVulnerable ? 0.85f : 0.15f; // Confidence estimada
                    LOG.info("Model returned class prediction: " + prediction[0]);
                } else if (outputValue instanceof long[][]) {
                    // Output es clase predicha en 2D
                    long[][] prediction = (long[][]) outputValue;
                    isVulnerable = prediction[0][0] == 1;
                    vulnerableProb = isVulnerable ? 0.85f : 0.15f;
                    LOG.info("Model returned 2D class prediction: " + prediction[0][0]);
                } else {
                    LOG.error("Unexpected output type: " + outputValue.getClass().getName());
                    return Optional.empty();
                }

                // Determinar categoría OWASP basada en las features más relevantes
                OWASPCategory category = determineOWASPCategory(features, isVulnerable);

                LOG.info(String.format("Prediction: %s (confidence: %.2f%%, category: %s)",
                        isVulnerable ? "VULNERABLE" : "SAFE",
                        vulnerableProb * 100,
                        category.getCode()));

                return Optional.of(new PredictionResult(
                        isVulnerable,
                        vulnerableProb,
                        category
                ));
            }

        } catch (Exception e) {
            LOG.error("Prediction failed", e);
            return Optional.empty();
        }
    }

    /**
     * Prepara las features normalizándolas y ordenándolas según el modelo espera
     */
    private float[] prepareFeatures(Map<String, Double> features) {
        float[] normalized = new float[featureNames.size()];

        for (int i = 0; i < featureNames.size(); i++) {
            String featureName = featureNames.get(i);
            Double value = features.getOrDefault(featureName, 0.0);

            // Normalizar usando StandardScaler: (x - mean) / scale
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

    /**
     * Determina la categoría OWASP basándose en las features más relevantes
     */
    private OWASPCategory determineOWASPCategory(Map<String, Double> features, boolean isVulnerable) {
        if (!isVulnerable) {
            return OWASPCategory.NONE;
        }

        // Mapeo de scores de features a categorías OWASP
        Map<OWASPCategory, Double> categoryScores = new HashMap<>();

        // A03: Injection
        double injectionScore = features.getOrDefault("injection_score", 0.0) * 2.0 +
                features.getOrDefault("injection_keywords", 0.0) * 0.5 +
                features.getOrDefault("injection_methods", 0.0) * 0.5;
        categoryScores.put(OWASPCategory.A03_INJECTION, injectionScore);

        // A10: SSRF
        double ssrfScore = features.getOrDefault("ssrf_score", 0.0) * 2.0 +
                features.getOrDefault("ssrf_keywords", 0.0) * 0.5 +
                features.getOrDefault("ssrf_methods", 0.0) * 0.5;
        categoryScores.put(OWASPCategory.A10_SSRF, ssrfScore);

        // A02: Cryptographic Failures
        double cryptoScore = features.getOrDefault("crypto_score", 0.0) * 2.0 +
                features.getOrDefault("crypto_methods", 0.0) * 0.5;
        categoryScores.put(OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES, cryptoScore);

        // A07: Authentication Failures
        double authScore = features.getOrDefault("auth_score", 0.0) * 2.0 +
                features.getOrDefault("auth_patterns", 0.0) * 0.5;
        categoryScores.put(OWASPCategory.A07_AUTHENTICATION_FAILURES, authScore);

        // A05: Security Misconfiguration
        double configScore = features.getOrDefault("config_score", 0.0) * 2.0 +
                features.getOrDefault("config_patterns", 0.0) * 0.5 +
                features.getOrDefault("config_methods", 0.0) * 0.5;
        categoryScores.put(OWASPCategory.A05_SECURITY_MISCONFIGURATION, configScore);

        // A09: Logging Failures
        double loggingScore = features.getOrDefault("logging_score", 0.0) * 2.0 +
                features.getOrDefault("logging_keywords", 0.0) * 0.5;
        categoryScores.put(OWASPCategory.A09_LOGGING_MONITORING_FAILURES, loggingScore);

        // A01: Broken Access Control (basado en file operations y user input)
        double accessScore = features.getOrDefault("has_file_ops", 0.0) * 1.5 +
                features.getOrDefault("pattern_user_input", 0.0) * 1.0 +
                features.getOrDefault("has_user_input", 0.0) * 0.5;
        categoryScores.put(OWASPCategory.A01_BROKEN_ACCESS_CONTROL, accessScore);

        // A06: Vulnerable Components
        double componentsScore = features.getOrDefault("components_keywords", 0.0) * 2.0 +
                features.getOrDefault("suspicious_imports_count", 0.0) * 0.5;
        categoryScores.put(OWASPCategory.A06_VULNERABLE_COMPONENTS, componentsScore);

        // A08: Software Integrity Failures (deserialización)
        double integrityScore = features.getOrDefault("dangerous_methods_count", 0.0) * 1.0;
        if (features.getOrDefault("pattern_user_input", 0.0) > 0) {
            integrityScore *= 1.5;
        }
        categoryScores.put(OWASPCategory.A08_SOFTWARE_INTEGRITY_FAILURES, integrityScore);

        // A04: Insecure Design (basado en complejidad)
        double designScore = features.getOrDefault("cyclomatic_complexity", 0.0) / 20.0 +
                features.getOrDefault("max_nesting_depth", 0.0) / 10.0;
        categoryScores.put(OWASPCategory.A04_INSECURE_DESIGN, designScore);

        // Encontrar la categoría con el score más alto
        return categoryScores.entrySet().stream()
                .filter(entry -> entry.getValue() > 0)
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse(OWASPCategory.A04_INSECURE_DESIGN); // Default si no hay scores
    }

    /**
     * Libera los recursos del modelo
     */
    public void close() {
        try {
            if (session != null) {
                session.close();
            }
            if (env != null) {
                env.close();
            }
            initialized = false;
            LOG.info("Model service closed");
        } catch (Exception e) {
            LOG.error("Error closing model service", e);
        }
    }

    /**
     * Resultado de la predicción del modelo
     */
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