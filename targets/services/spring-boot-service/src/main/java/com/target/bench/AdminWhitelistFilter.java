// SECURITY-REVIEWED: 2026-07-24 | RULES: v2.6.0-draft
package com.target.bench;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;

/**
 * 漏洞核心：模拟零信任/SSO 拦截器的静态资源白名单绕过。
 *
 * 真实场景：拦截器保护 /admin/** 等管理路径，但白名单 .js/.html/.css 等静态资源后缀。
 * 漏洞：拦截器用 getRequestURI() 判断后缀，getRequestURI() 保留 ;.js → endsWith(".js") → 放行
 * 但 Tomcat 将 ; 视为路径参数分隔符，剥离 ;.js → servletPath=/api/users/admin/dashboard → 正常路由
 *
 * 攻击：GET /api/users/admin/dashboard;.js → 拦截器放行 → Tomcat 剥离 → /api/users/admin/dashboard → 返回管理数据
 */
public class AdminWhitelistFilter implements Filter {

    private static final Set<String> STATIC_EXTENSIONS = Set.of(
        ".js", ".html", ".css", ".ico", ".png", ".svg", ".jpg", ".gif", ".woff", ".woff2", ".map"
    );

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        String requestURI = req.getRequestURI();
        String servletPath = req.getServletPath();

        // 拦截包含 /admin/ 路径段的所有请求（基于 servletPath，即规范化后的路径）
        // 匹配规则：servletPath 含 "/admin/" 路径段，或以 "/admin" 开头/结尾
        // 如 /admin/dashboard（顶层）、/api/users/admin/dashboard（路径段内）
        // 但白名单静态资源后缀（基于 requestURI，即原始未剥离分号的 URI）
        // 漏洞：requestURI.endsWith(".js") → 误判为静态文件 → 放行
        //       Tomcat 副离 ;.js → servletPath 不含 .js → 正常路由到 admin endpoint
        if (servletPath.contains("/admin/") || servletPath.startsWith("/admin") || servletPath.endsWith("/admin")) {
            boolean isStatic = STATIC_EXTENSIONS.stream()
                .anyMatch(ext -> requestURI.endsWith(ext));
            if (!isStatic) {
                HttpServletResponse res = (HttpServletResponse) response;
                res.setStatus(403);
                res.setContentType("application/json");
                res.getWriter().write("{\"error\":\"Admin access denied\",\"status\":403}");
                return;
            }
        }

        chain.doFilter(request, response);
    }
}
