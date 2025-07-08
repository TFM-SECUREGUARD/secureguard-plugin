package com.secureguard.inspections;

import com.intellij.codeInspection.LocalQuickFix;
import com.intellij.codeInspection.ProblemDescriptor;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.Messages;
import org.jetbrains.annotations.Nls;
import org.jetbrains.annotations.NotNull;

/**
 * Quick Fix para problemas de autenticación
 */
class AuthenticationQuickFix implements LocalQuickFix {
    @Nls
    @NotNull
    @Override
    public String getName() {
        return "Fix authentication issue";
    }

    @Nls
    @NotNull
    @Override
    public String getFamilyName() {
        return "SecureGuard Authentication Fix";
    }

    @Override
    public void applyFix(@NotNull Project project, @NotNull ProblemDescriptor descriptor) {
        String suggestion =
                "Authentication Best Practices:\n\n" +
                        "1. Never hardcode passwords:\n" +
                        "   // Bad:\n" +
                        "   String password = \"admin123\";\n\n" +
                        "   // Good:\n" +
                        "   String password = System.getenv(\"APP_PASSWORD\");\n\n" +
                        "2. Use strong password hashing:\n" +
                        "   BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();\n" +
                        "   String hashedPassword = encoder.encode(plainPassword);\n\n" +
                        "3. Implement secure session management:\n" +
                        "   - Use secure session IDs\n" +
                        "   - Set appropriate session timeouts\n" +
                        "   - Regenerate session IDs after login\n\n" +
                        "4. Implement account lockout after failed attempts\n" +
                        "5. Use multi-factor authentication when possible";

        Messages.showInfoMessage(project, suggestion, "SecureGuard - Authentication Security");
    }
}

/**
 * Quick Fix para control de acceso
 */
class AccessControlQuickFix implements LocalQuickFix {
    @Nls
    @NotNull
    @Override
    public String getName() {
        return "Fix access control issue";
    }

    @Nls
    @NotNull
    @Override
    public String getFamilyName() {
        return "SecureGuard Access Control Fix";
    }

    @Override
    public void applyFix(@NotNull Project project, @NotNull ProblemDescriptor descriptor) {
        String suggestion =
                "Access Control Best Practices:\n\n" +
                        "1. Validate file paths to prevent directory traversal:\n" +
                        "   // Vulnerable:\n" +
                        "   File file = new File(\"/uploads/\" + userInput);\n\n" +
                        "   // Secure:\n" +
                        "   String filename = Paths.get(userInput).getFileName().toString();\n" +
                        "   if (filename.contains(\"..\")) {\n" +
                        "       throw new SecurityException(\"Invalid filename\");\n" +
                        "   }\n" +
                        "   File file = new File(\"/uploads/\" + filename);\n\n" +
                        "2. Implement proper authorization checks:\n" +
                        "   @PreAuthorize(\"hasRole('ADMIN')\")\n" +
                        "   public void adminOperation() { }\n\n" +
                        "3. Use whitelisting for file types:\n" +
                        "   Set<String> ALLOWED_EXTENSIONS = Set.of(\".jpg\", \".png\", \".pdf\");\n\n" +
                        "4. Validate all user inputs\n" +
                        "5. Apply principle of least privilege";

        Messages.showInfoMessage(project, suggestion, "SecureGuard - Access Control");
    }
}