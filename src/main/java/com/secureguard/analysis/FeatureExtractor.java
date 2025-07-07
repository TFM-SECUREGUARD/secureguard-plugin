package com.secureguard.analysis;

import com.intellij.psi.*;
import com.intellij.psi.util.PsiTreeUtil;
import org.jetbrains.annotations.NotNull;

import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Extrae las features del código Java para el modelo ML
 * IMPORTANTE: Genera EXACTAMENTE las mismas 59 features que el modelo Python espera
 * según feature_mapping.json
 */
public class FeatureExtractor {

    // Patrones peligrosos - ajustados para coincidir con el modelo Python
    private static final Set<String> CRYPTO_METHODS = Set.of(
            "MD5", "SHA1", "SHA-1", "DES", "RC4", "Base64",
            "MessageDigest", "Cipher", "KeyGenerator"
    );

    private static final Set<String> INJECTION_KEYWORDS = Set.of(
            "executeQuery", "executeUpdate", "execute", "createStatement",
            "prepareStatement", "prepareCall", "nativeSQL", "sql", "query"
    );

    private static final Set<String> CONFIG_PATTERNS = Set.of(
            "printStackTrace", "System.out", "System.err", "DEBUG",
            "Logger", "log4j", "slf4j", "commons-logging"
    );

    private static final Set<String> AUTH_PATTERNS = Set.of(
            "password", "passwd", "pwd", "secret", "token", "session",
            "cookie", "authentication", "credential", "login"
    );

    private static final Set<String> LOGGING_KEYWORDS = Set.of(
            "Logger", "log", "Log4j", "Slf4j", "LogFactory",
            "getLogger", "debug", "info", "warn", "error"
    );

    private static final Set<String> SSRF_KEYWORDS = Set.of(
            "URL", "URLConnection", "HttpURLConnection", "HttpClient",
            "RestTemplate", "WebClient", "openConnection", "connect"
    );

    private static final Set<String> DANGEROUS_METHODS = Set.of(
            "exec", "getRuntime", "ProcessBuilder", "eval",
            "readObject", "ObjectInputStream", "XMLDecoder",
            "load", "include", "require", "file_get_contents"
    );

    private static final Set<String> USER_INPUT_PATTERNS = Set.of(
            "getParameter", "getHeader", "getCookie", "getQueryString",
            "getInputStream", "getReader", "readLine", "nextLine",
            "request.get", "params.get", "args", "argv"
    );

    /**
     * Extrae las 59 features en el orden exacto que espera el modelo
     */
    public Map<String, Double> extractFeatures(@NotNull PsiElement element) {
        Map<String, Double> features = new LinkedHashMap<>(); // LinkedHashMap para mantener el orden

        String code = element.getText();
        if (code == null) code = "";

        // Extraer features en el orden exacto del feature_mapping.json

        // 1. code_length
        features.put("code_length", (double) code.length());

        // 2. num_lines
        String[] lines = code.split("\n");
        features.put("num_lines", (double) lines.length);

        // 3. num_empty_lines
        long emptyLines = Arrays.stream(lines).filter(line -> line.trim().isEmpty()).count();
        features.put("num_empty_lines", (double) emptyLines);

        // 4. avg_line_length
        double avgLineLength = lines.length > 0 ?
                Arrays.stream(lines).mapToInt(String::length).average().orElse(0) : 0;
        features.put("avg_line_length", avgLineLength);

        // 5. max_line_length
        int maxLineLength = Arrays.stream(lines).mapToInt(String::length).max().orElse(0);
        features.put("max_line_length", (double) maxLineLength);

        // 6-13. Contadores básicos
        features.put("num_semicolons", (double) countOccurrences(code, ";"));
        features.put("num_braces", (double) (countOccurrences(code, "{") + countOccurrences(code, "}")));
        features.put("num_parentheses", (double) (countOccurrences(code, "(") + countOccurrences(code, ")")));
        features.put("num_brackets", (double) (countOccurrences(code, "[") + countOccurrences(code, "]")));
        features.put("num_strings", (double) countStringLiterals(element));
        features.put("num_comments", (double) countComments(code));
        features.put("num_dots", (double) countOccurrences(code, "."));
        features.put("num_commas", (double) countOccurrences(code, ","));

        // 14. num_operators
        features.put("num_operators", (double) countOperators(code));

        // 15-16. Crypto features
        double cryptoMethods = countPatternOccurrences(code, CRYPTO_METHODS);
        features.put("crypto_methods", cryptoMethods);
        features.put("crypto_score", cryptoMethods > 0 ? Math.min(cryptoMethods / 10.0, 1.0) : 0.0);

        // 17-20. Injection features
        double injectionKeywords = countPatternOccurrences(code, INJECTION_KEYWORDS);
        features.put("injection_keywords", injectionKeywords);
        features.put("injection_patterns", hasInjectionPatterns(code) ? 1.0 : 0.0);
        features.put("injection_methods", countInjectionMethods(element));
        features.put("injection_score", calculateInjectionScore(code, injectionKeywords));

        // 21-23. Config features
        double configPatterns = countPatternOccurrences(code, CONFIG_PATTERNS);
        features.put("config_patterns", configPatterns);
        features.put("config_methods", countConfigMethods(element));
        features.put("config_score", configPatterns > 0 ? Math.min(configPatterns / 10.0, 1.0) : 0.0);

        // 24. components_keywords
        features.put("components_keywords", countVulnerableComponents(code));

        // 25-26. Auth features
        double authPatterns = countPatternOccurrences(code, AUTH_PATTERNS);
        features.put("auth_patterns", authPatterns);
        features.put("auth_score", authPatterns > 0 ? Math.min(authPatterns / 10.0, 1.0) : 0.0);

        // 27-29. Logging features
        double loggingKeywords = countPatternOccurrences(code, LOGGING_KEYWORDS);
        features.put("logging_keywords", loggingKeywords);
        features.put("logging_methods", countLoggingMethods(element));
        features.put("logging_score", loggingKeywords > 0 ? Math.min(loggingKeywords / 10.0, 1.0) : 0.0);

        // 30-32. SSRF features
        double ssrfKeywords = countPatternOccurrences(code, SSRF_KEYWORDS);
        features.put("ssrf_keywords", ssrfKeywords);
        features.put("ssrf_methods", countSSRFMethods(element));
        features.put("ssrf_score", ssrfKeywords > 0 ? Math.min(ssrfKeywords / 10.0, 1.0) : 0.0);

        // 33-34. Pattern features
        features.put("pattern_user_input", hasUserInputPattern(code) ? 1.0 : 0.0);
        features.put("pattern_network_operations", hasNetworkOperations(code) ? 1.0 : 0.0);

        // 35-36. Dangerous features
        features.put("dangerous_methods_count", countPatternOccurrences(code, DANGEROUS_METHODS));
        features.put("suspicious_imports_count", countSuspiciousImports(element));

        // 37-43. Control flow keywords
        features.put("num_if", (double) countKeyword(code, "if"));
        features.put("num_for", (double) countKeyword(code, "for"));
        features.put("num_try", (double) countKeyword(code, "try"));
        features.put("num_catch", (double) countKeyword(code, "catch"));
        features.put("num_throw", (double) countKeyword(code, "throw"));
        features.put("num_return", (double) countKeyword(code, "return"));
        features.put("num_break", (double) countKeyword(code, "break"));

        // 44. num_annotations
        features.put("num_annotations", (double) countAnnotations(element));

        // 45-46. Complexity features
        features.put("cyclomatic_complexity", calculateCyclomaticComplexity(element));
        features.put("max_nesting_depth", calculateMaxNestingDepth(element));

        // 47-48. Identifier features
        double[] identifierStats = calculateIdentifierStats(element);
        features.put("avg_identifier_length", identifierStats[0]);
        features.put("max_identifier_length", identifierStats[1]);

        // 49-53. Boolean flags
        features.put("has_user_input", hasUserInput(code) ? 1.0 : 0.0);
        features.put("has_file_ops", hasFileOperations(code) ? 1.0 : 0.0);
        features.put("has_network_ops", hasNetworkOperations(code) ? 1.0 : 0.0);
        features.put("has_db_ops", hasDatabaseOperations(code) ? 1.0 : 0.0);
        features.put("has_output", hasOutputOperations(code) ? 1.0 : 0.0);

        // 54-56. Method features
        features.put("num_methods", (double) countMethods(element));
        double[] methodParams = calculateMethodParams(element);
        features.put("avg_params_per_method", methodParams[0]);
        features.put("max_params_per_method", methodParams[1]);

        // 57-59. Type usage features
        features.put("uses_string", usesStringType(element) ? 1.0 : 0.0);
        features.put("uses_int", usesIntType(element) ? 1.0 : 0.0);
        features.put("uses_array", usesArrayType(element) ? 1.0 : 0.0);

        return features;
    }

    // Métodos auxiliares para el cálculo de features

    private int countOccurrences(String text, String pattern) {
        int count = 0;
        int index = 0;
        while ((index = text.indexOf(pattern, index)) != -1) {
            count++;
            index += pattern.length();
        }
        return count;
    }

    private int countKeyword(String code, String keyword) {
        Pattern pattern = Pattern.compile("\\b" + keyword + "\\b");
        return (int) pattern.matcher(code).results().count();
    }

    private double countPatternOccurrences(String code, Set<String> patterns) {
        String lowerCode = code.toLowerCase();
        return patterns.stream()
                .mapToDouble(pattern -> {
                    Pattern p = Pattern.compile("\\b" + pattern.toLowerCase() + "\\b");
                    return p.matcher(lowerCode).results().count();
                })
                .sum();
    }

    private int countStringLiterals(PsiElement element) {
        return PsiTreeUtil.findChildrenOfType(element, PsiLiteralExpression.class).stream()
                .filter(literal -> literal.getType() != null &&
                        literal.getType().equalsToText("java.lang.String"))
                .mapToInt(e -> 1)
                .sum();
    }

    private int countComments(String code) {
        int count = 0;
        // Single line comments
        Pattern singleLine = Pattern.compile("//.*$", Pattern.MULTILINE);
        count += (int) singleLine.matcher(code).results().count();

        // Multi-line comments
        Pattern multiLine = Pattern.compile("/\\*.*?\\*/", Pattern.DOTALL);
        count += (int) multiLine.matcher(code).results().count();

        return count;
    }

    private int countOperators(String code) {
        String[] operators = {
                "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", ">>>=",
                "++", "--", "==", "!=", "<=", ">=", "&&", "||", "<<", ">>", ">>>",
                "+", "-", "*", "/", "%", "&", "|", "^", "~", "!", "<", ">"
        };

        int count = 0;
        for (String op : operators) {
            count += countOccurrences(code, op);
        }
        return count;
    }

    private boolean hasInjectionPatterns(String code) {
        // Buscar patrones de concatenación SQL
        return code.contains("\" +") && containsSQLKeywords(code);
    }

    private boolean containsSQLKeywords(String code) {
        String[] sqlKeywords = {"SELECT", "INSERT", "UPDATE", "DELETE", "FROM",
                "WHERE", "DROP", "CREATE", "ALTER", "EXEC", "UNION"};
        String upperCode = code.toUpperCase();
        return Arrays.stream(sqlKeywords).anyMatch(upperCode::contains);
    }

    private double countInjectionMethods(PsiElement element) {
        Collection<PsiMethodCallExpression> methodCalls =
                PsiTreeUtil.findChildrenOfType(element, PsiMethodCallExpression.class);

        return methodCalls.stream()
                .filter(call -> {
                    String methodName = call.getMethodExpression().getReferenceName();
                    return methodName != null && INJECTION_KEYWORDS.contains(methodName);
                })
                .count();
    }

    private double calculateInjectionScore(String code, double keywordCount) {
        if (keywordCount == 0) return 0.0;

        // Factor adicional si hay concatenación de strings
        double concatenationFactor = (code.contains("\" +") || code.contains("+ \"")) ? 1.5 : 1.0;

        return Math.min((keywordCount / 10.0) * concatenationFactor, 1.0);
    }

    private double countConfigMethods(PsiElement element) {
        Collection<PsiMethodCallExpression> methodCalls =
                PsiTreeUtil.findChildrenOfType(element, PsiMethodCallExpression.class);

        Set<String> configMethodNames = Set.of(
                "printStackTrace", "setProperty", "getProperty", "loadProperties"
        );

        return methodCalls.stream()
                .filter(call -> {
                    String methodName = call.getMethodExpression().getReferenceName();
                    return methodName != null && configMethodNames.contains(methodName);
                })
                .count();
    }

    private double countVulnerableComponents(String code) {
        String[] vulnerableLibs = {
                "struts", "spring", "jackson", "log4j", "commons-collections",
                "commons-fileupload", "fastjson", "xstream"
        };

        double count = 0;
        String lowerCode = code.toLowerCase();
        for (String lib : vulnerableLibs) {
            if (lowerCode.contains(lib)) count++;
        }
        return count;
    }

    private double countLoggingMethods(PsiElement element) {
        Collection<PsiMethodCallExpression> methodCalls =
                PsiTreeUtil.findChildrenOfType(element, PsiMethodCallExpression.class);

        Set<String> loggingMethods = Set.of(
                "debug", "info", "warn", "error", "trace", "fatal", "log"
        );

        return methodCalls.stream()
                .filter(call -> {
                    String methodName = call.getMethodExpression().getReferenceName();
                    return methodName != null && loggingMethods.contains(methodName.toLowerCase());
                })
                .count();
    }

    private double countSSRFMethods(PsiElement element) {
        Collection<PsiMethodCallExpression> methodCalls =
                PsiTreeUtil.findChildrenOfType(element, PsiMethodCallExpression.class);

        Set<String> ssrfMethods = Set.of(
                "openConnection", "connect", "getInputStream", "openStream",
                "execute", "get", "post", "put", "delete"
        );

        return methodCalls.stream()
                .filter(call -> {
                    String methodName = call.getMethodExpression().getReferenceName();
                    return methodName != null && ssrfMethods.contains(methodName);
                })
                .count();
    }

    private boolean hasUserInputPattern(String code) {
        return USER_INPUT_PATTERNS.stream().anyMatch(pattern ->
                code.contains(pattern));
    }

    private boolean hasNetworkOperations(String code) {
        String[] networkPatterns = {
                "URL", "URLConnection", "Socket", "ServerSocket",
                "HttpClient", "HttpURLConnection", "InetAddress"
        };
        return Arrays.stream(networkPatterns).anyMatch(code::contains);
    }

    private double countSuspiciousImports(PsiElement element) {
        if (!(element.getContainingFile() instanceof PsiJavaFile)) {
            return 0.0;
        }

        PsiJavaFile javaFile = (PsiJavaFile) element.getContainingFile();
        PsiImportList importList = javaFile.getImportList();
        if (importList == null) return 0.0;

        String[] suspiciousPackages = {
                "java.io.ObjectInputStream", "java.beans.XMLDecoder",
                "java.lang.Runtime", "java.lang.ProcessBuilder",
                "javax.script", "java.net.URL"
        };

        PsiImportStatement[] imports = importList.getImportStatements();
        return Arrays.stream(imports)
                .filter(imp -> {
                    String importText = imp.getQualifiedName();
                    return importText != null && Arrays.stream(suspiciousPackages)
                            .anyMatch(importText::contains);
                })
                .count();
    }

    private int countAnnotations(PsiElement element) {
        return PsiTreeUtil.findChildrenOfType(element, PsiAnnotation.class).size();
    }

    private double calculateCyclomaticComplexity(PsiElement element) {
        int complexity = 1; // Base complexity

        // Decisiones
        complexity += PsiTreeUtil.findChildrenOfType(element, PsiIfStatement.class).size();
        complexity += PsiTreeUtil.findChildrenOfType(element, PsiConditionalExpression.class).size();

        // Loops
        complexity += PsiTreeUtil.findChildrenOfType(element, PsiForStatement.class).size();
        complexity += PsiTreeUtil.findChildrenOfType(element, PsiWhileStatement.class).size();
        complexity += PsiTreeUtil.findChildrenOfType(element, PsiDoWhileStatement.class).size();
        complexity += PsiTreeUtil.findChildrenOfType(element, PsiForeachStatement.class).size();

        // Switch cases
        Collection<PsiSwitchStatement> switches =
                PsiTreeUtil.findChildrenOfType(element, PsiSwitchStatement.class);
        for (PsiSwitchStatement switchStmt : switches) {
            PsiCodeBlock body = switchStmt.getBody();
            if (body != null) {
                PsiStatement[] statements = body.getStatements();
                // Contar labels de case
                for (PsiStatement stmt : statements) {
                    if (stmt instanceof PsiSwitchLabelStatement) {
                        complexity++;
                    }
                }
            }
        }

        // Operadores lógicos
        complexity += countOccurrences(element.getText(), "&&");
        complexity += countOccurrences(element.getText(), "||");

        // Catch blocks
        complexity += PsiTreeUtil.findChildrenOfType(element, PsiCatchSection.class).size();

        return complexity;
    }

    private double calculateMaxNestingDepth(PsiElement element) {
        return calculateNestingDepthRecursive(element, 0);
    }

    private int calculateNestingDepthRecursive(PsiElement element, int currentDepth) {
        int maxDepth = currentDepth;

        if (element instanceof PsiCodeBlock ||
                element instanceof PsiIfStatement ||
                element instanceof PsiForStatement ||
                element instanceof PsiWhileStatement ||
                element instanceof PsiDoWhileStatement ||
                element instanceof PsiTryStatement ||
                element instanceof PsiSwitchStatement) {
            currentDepth++;
        }

        for (PsiElement child : element.getChildren()) {
            int childDepth = calculateNestingDepthRecursive(child, currentDepth);
            maxDepth = Math.max(maxDepth, childDepth);
        }

        return maxDepth;
    }

    private double[] calculateIdentifierStats(PsiElement element) {
        Collection<PsiIdentifier> identifiers =
                PsiTreeUtil.findChildrenOfType(element, PsiIdentifier.class);

        if (identifiers.isEmpty()) {
            return new double[]{0.0, 0.0};
        }

        List<Integer> lengths = identifiers.stream()
                .map(id -> id.getText().length())
                .collect(Collectors.toList());

        double avg = lengths.stream().mapToInt(Integer::intValue).average().orElse(0);
        int max = lengths.stream().mapToInt(Integer::intValue).max().orElse(0);

        return new double[]{avg, max};
    }

    private boolean hasUserInput(String code) {
        return USER_INPUT_PATTERNS.stream().anyMatch(pattern ->
                Pattern.compile("\\b" + pattern + "\\b").matcher(code).find());
    }

    private boolean hasFileOperations(String code) {
        String[] filePatterns = {
                "File", "FileInputStream", "FileOutputStream", "FileReader",
                "FileWriter", "RandomAccessFile", "Path", "Files"
        };
        return Arrays.stream(filePatterns).anyMatch(pattern ->
                Pattern.compile("\\b" + pattern + "\\b").matcher(code).find());
    }

    private boolean hasDatabaseOperations(String code) {
        String[] dbPatterns = {
                "Connection", "Statement", "PreparedStatement", "ResultSet",
                "DataSource", "EntityManager", "Session", "Query"
        };
        return Arrays.stream(dbPatterns).anyMatch(pattern ->
                Pattern.compile("\\b" + pattern + "\\b").matcher(code).find());
    }

    private boolean hasOutputOperations(String code) {
        String[] outputPatterns = {
                "System.out", "System.err", "PrintWriter", "PrintStream",
                "Writer", "OutputStream", "response.getWriter"
        };
        return Arrays.stream(outputPatterns).anyMatch(code::contains);
    }

    private int countMethods(PsiElement element) {
        return PsiTreeUtil.findChildrenOfType(element, PsiMethod.class).size();
    }

    private double[] calculateMethodParams(PsiElement element) {
        Collection<PsiMethod> methods = PsiTreeUtil.findChildrenOfType(element, PsiMethod.class);

        if (methods.isEmpty()) {
            // Si el elemento mismo es un método
            if (element instanceof PsiMethod) {
                int params = ((PsiMethod) element).getParameterList().getParametersCount();
                return new double[]{params, params};
            }
            return new double[]{0.0, 0.0};
        }

        List<Integer> paramCounts = methods.stream()
                .map(m -> m.getParameterList().getParametersCount())
                .collect(Collectors.toList());

        double avg = paramCounts.stream().mapToInt(Integer::intValue).average().orElse(0);
        int max = paramCounts.stream().mapToInt(Integer::intValue).max().orElse(0);

        return new double[]{avg, max};
    }

    private boolean usesStringType(PsiElement element) {
        Collection<PsiVariable> variables = PsiTreeUtil.findChildrenOfType(element, PsiVariable.class);
        return variables.stream().anyMatch(var -> {
            PsiType type = var.getType();
            return type.equalsToText("java.lang.String") || type.equalsToText("String");
        });
    }

    private boolean usesIntType(PsiElement element) {
        Collection<PsiVariable> variables = PsiTreeUtil.findChildrenOfType(element, PsiVariable.class);
        return variables.stream().anyMatch(var -> {
            PsiType type = var.getType();
            return type.equalsToText("int") || type.equalsToText("Integer") ||
                    type.equalsToText("java.lang.Integer");
        });
    }

    private boolean usesArrayType(PsiElement element) {
        Collection<PsiVariable> variables = PsiTreeUtil.findChildrenOfType(element, PsiVariable.class);
        return variables.stream().anyMatch(var -> var.getType() instanceof PsiArrayType);
    }
}