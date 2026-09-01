package com.airlab.admin.lab;

import com.airlab.admin.common.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.util.List;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 교육용으로 의도적으로 취약한 API입니다.
 *
 * <p>실제 admin_db 또는 다른 서비스 API를 조회하지 않으며 모든 개인정보,
 * 내부 설정 및 플래그는 합성 데이터입니다. ADMIN_LAB_ENABLED=true일 때만
 * 빈으로 등록됩니다.</p>
 */
@RestController
@RequestMapping("/api/admin/lab")
@ConditionalOnProperty(name = "admin.lab.enabled", havingValue = "true")
public class AdminSecurityLabController {

    private static final List<LabAdminProfile> PROFILES = List.of(
            new LabAdminProfile(
                    1L,
                    "lab_operator",
                    "운영 관리자(실습)",
                    "OPERATOR",
                    "010-0000-1001",
                    "operator@lab.invalid",
                    "SYNTHETIC-EMP-1001",
                    null),
            new LabAdminProfile(
                    2L,
                    "lab_auditor",
                    "감사 관리자(실습)",
                    "AUDITOR",
                    "010-0000-1002",
                    "auditor@lab.invalid",
                    "SYNTHETIC-EMP-1002",
                    "FLAG{LAB_IDOR_PROFILE_02}"),
            new LabAdminProfile(
                    3L,
                    "lab_super",
                    "최고 관리자(실습)",
                    "SUPER_ADMIN",
                    "010-0000-1003",
                    "super@lab.invalid",
                    "SYNTHETIC-EMP-1003",
                    null));

    @GetMapping("/overview")
    public ApiResponse<LabOverview> overview(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        String loginId = String.valueOf(session.getAttribute("ADMIN_LOGIN_ID"));
        String role = String.valueOf(session.getAttribute("ADMIN_ROLE"));

        return ApiResponse.ok(
                new LabOverview(
                        true,
                        "LAB ONLY - 모든 개인정보와 비밀값은 합성 데이터입니다.",
                        loginId,
                        role,
                        List.of(
                                "약한 비밀번호 정책",
                                "IDOR/BOLA",
                                "불충분한 권한 검증",
                                "상세 오류 정보 노출")),
                "보안 실습 환경이 활성화되었습니다.");
    }

    /**
     * 취약점 LAB-01: 로그인만 확인하고 요청한 프로필의 소유권/역할을 확인하지 않습니다.
     */
    @GetMapping("/admins/{id}")
    public ApiResponse<LabAdminProfile> profile(@PathVariable long id) {
        LabAdminProfile profile = PROFILES.stream()
                .filter(item -> item.id() == id)
                .findFirst()
                .orElseThrow(() -> new LabRecordNotFoundException(id));

        return ApiResponse.ok(
                profile,
                "LAB-01: 객체 단위 권한 검증 없이 합성 관리자 프로필을 반환했습니다.");
    }

    /**
     * 취약점 LAB-02: 역할을 검사하지 않아 AUDITOR/OPERATOR도 전체 내보내기가 가능합니다.
     */
    @GetMapping("/export")
    public ApiResponse<LabExport> export(
            @RequestParam(defaultValue = "summary") String scope,
            HttpServletRequest request) {

        HttpSession session = request.getSession(false);
        String role = String.valueOf(session.getAttribute("ADMIN_ROLE"));

        return ApiResponse.ok(
                new LabExport(
                        scope,
                        role,
                        PROFILES,
                        "SYNTHETIC-ACCOUNT-NO-000-000-000000",
                        "FLAG{LAB_BROKEN_ROLE_EXPORT}"),
                "LAB-02: 역할 검증 없이 합성 민감정보 내보내기를 허용했습니다.");
    }

    /**
     * 취약점 LAB-03: 운영 오류 응답에 내부 경로와 가짜 토큰을 과도하게 노출합니다.
     */
    @GetMapping("/debug")
    public ApiResponse<LabDebugInfo> debug(
            @RequestParam(defaultValue = "normal") String mode) {

        return ApiResponse.ok(
                new LabDebugInfo(
                        mode,
                        "/srv/youngkeke-lab/deployments/admin-lab.war",
                        "jdbc:mysql://10.255.30.11:3306/admin_lab_synthetic",
                        "LAB-DEMO-TOKEN-NOT-A-REAL-SECRET",
                        "FLAG{LAB_VERBOSE_ERROR_DISCLOSURE}"),
                "LAB-03: 상세 오류 정보가 과도하게 노출되었습니다.");
    }

    /**
     * 취약점 LAB-04: 실제 계정은 변경하지 않고 약한 정책 판정만 재현합니다.
     */
    @PostMapping("/password-check")
    public ApiResponse<Map<String, Object>> passwordCheck(
            @RequestBody PasswordCheckRequest input) {

        String password = input.password() == null ? "" : input.password();
        boolean acceptedByWeakPolicy = password.length() >= 4;

        return ApiResponse.ok(
                Map.of(
                        "acceptedByWeakPolicy", acceptedByWeakPolicy,
                        "minimumLength", 4,
                        "realAccountChanged", false,
                        "flag", acceptedByWeakPolicy
                                ? "FLAG{LAB_WEAK_PASSWORD_POLICY}"
                                : ""),
                acceptedByWeakPolicy
                        ? "LAB-04: 지나치게 약한 비밀번호 정책을 통과했습니다."
                        : "4자 이상을 입력해야 취약 정책을 재현할 수 있습니다.");
    }

    public record LabOverview(
            boolean enabled,
            String warning,
            String currentLoginId,
            String currentRole,
            List<String> scenarios) {
    }

    public record LabAdminProfile(
            Long id,
            String loginId,
            String displayName,
            String role,
            String phone,
            String email,
            String employeeNumber,
            String flag) {
    }

    public record LabExport(
            String requestedScope,
            String requesterRole,
            List<LabAdminProfile> admins,
            String fakeSettlementAccount,
            String flag) {
    }

    public record LabDebugInfo(
            String mode,
            String deploymentPath,
            String fakeJdbcUrl,
            String fakeToken,
            String flag) {
    }

    public record PasswordCheckRequest(String password) {
    }

    private static class LabRecordNotFoundException extends RuntimeException {
        LabRecordNotFoundException(long id) {
            super("LAB profile not found: " + id);
        }
    }
}
