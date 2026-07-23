package com.target.bench;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 漏洞核心：模拟旧版 Tomcat 的 ..;/ 分号路径参数穿越行为。
 *
 * 真实场景：nginx 不处理 ..;/ → 按最长前缀匹配路由到 Spring Boot →
 * 旧版 Tomcat 把 ; 当路径参数分隔符剥离，..;/ → ../ → 穿越到 /actuator/env。
 *
 * Tomcat 10 已正确处理穿越（servletPath=/actuator/env），但 DispatcherServlet
 * 可能仍用原始 requestURI 路由匹配导致 404。
 * 此 Filter 检测 Tomcat 规范化后的 servletPath 与原始 requestURI 不同时，
 * 直接 forward 到规范化的 servletPath，确保 actuator endpoint 正确匹配。
 *
 * 需要配合 relaxed-path-chars 让 ; 通过 Tomcat 字符检查。
 */
public class SemicolonPathFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        String servletPath = req.getServletPath();
        String requestURI = req.getRequestURI();

        // Tomcat 已把 ..;/..;/actuator/env 规范化为 servletPath=/actuator/env
        // 但 DispatcherServlet 用 requestURI 路由匹配 → 404
        // 直接 forward 到 servletPath（规范化路径），绕过 DispatcherServlet 路由匹配
        if (!servletPath.equals(requestURI) && servletPath.startsWith("/actuator")) {
            request.getRequestDispatcher(servletPath).forward(request, response);
        } else {
            chain.doFilter(request, response);
        }
    }
}
