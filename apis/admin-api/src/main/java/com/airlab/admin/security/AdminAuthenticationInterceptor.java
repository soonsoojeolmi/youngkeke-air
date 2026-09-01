package com.airlab.admin.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class AdminAuthenticationInterceptor implements HandlerInterceptor {

    public static final String SESSION_ADMIN_ID = "ADMIN_ID";
    public static final String SESSION_LOGIN_ID = "ADMIN_LOGIN_ID";
    public static final String SESSION_DISPLAY_NAME = "ADMIN_DISPLAY_NAME";
    public static final String SESSION_ROLE = "ADMIN_ROLE";

    @Override
    public boolean preHandle(
            HttpServletRequest request,
            HttpServletResponse response,
            Object handler) throws Exception {

        HttpSession session = request.getSession(false);
        if (session != null && session.getAttribute(SESSION_ADMIN_ID) != null) {
            String role = String.valueOf(session.getAttribute(SESSION_ROLE));
            String path = request.getRequestURI();

            if (isAuthorized(role, path)) {
                return true;
            }

            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setCharacterEncoding("UTF-8");
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(
                    "{\"success\":false,\"data\":null,"
                            + "\"message\":\"해당 관리자 역할에 허용되지 않은 기능입니다.\"}");
            return false;
        }

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setCharacterEncoding("UTF-8");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(
                "{\"success\":false,\"data\":null,"
                        + "\"message\":\"관리자 로그인이 필요합니다.\"}");
        return false;
    }

    private boolean isAuthorized(String role, String path) {
        if ("SUPER_ADMIN".equals(role) || "ADMIN".equals(role)) {
            return true;
        }

        // 보안 실습 API는 의도적으로 역할 검증이 빠진 상태를 재현합니다.
        // 반환 데이터는 모두 합성 데이터이며 실제 admin_db 행을 조회하지 않습니다.
        if (path.contains("/api/admin/lab/")) {
            return true;
        }

        if ("AUDITOR".equals(role)) {
            return path.contains("/api/admin/audit-logs");
        }

        if ("OPERATOR".equals(role)) {
            return path.contains("/api/admin/reservations")
                    || path.contains("/api/admin/qna")
                    || path.contains("/api/admin/crew")
                    || path.contains("/api/admin/partner/");
        }

        return false;
    }
}
