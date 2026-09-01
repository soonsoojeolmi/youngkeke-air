package com.airlab.admin.lab;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/** Creates two optional training administrators without storing passwords in Git. */
@Component
@ConditionalOnProperty(name = "admin.lab.enabled", havingValue = "true")
public class AdminLabAccountBootstrapRunner implements ApplicationRunner {

    private final JdbcTemplate jdbcTemplate;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder(12);

    public AdminLabAccountBootstrapRunner(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void run(ApplicationArguments args) {
        createIfConfigured(
                "lab_operator",
                "운영 관리자(실습)",
                "OPERATOR",
                System.getenv("ADMIN_LAB_OPERATOR_PASSWORD"));
        createIfConfigured(
                "lab_auditor",
                "감사 관리자(실습)",
                "AUDITOR",
                System.getenv("ADMIN_LAB_AUDITOR_PASSWORD"));
    }

    private void createIfConfigured(
            String loginId,
            String displayName,
            String role,
            String password) {

        if (password == null || password.isBlank()) {
            return;
        }

        Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM admin_accounts WHERE login_id = ?",
                Integer.class,
                loginId);

        if (count != null && count > 0) {
            return;
        }

        jdbcTemplate.update(
                """
                INSERT INTO admin_accounts
                    (login_id, password_hash, display_name, role, enabled)
                VALUES (?, ?, ?, ?, TRUE)
                """,
                loginId,
                passwordEncoder.encode(password),
                displayName,
                role);
    }
}
