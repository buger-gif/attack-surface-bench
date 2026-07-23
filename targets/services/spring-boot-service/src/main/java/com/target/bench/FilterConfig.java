package com.target.bench;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

/**
 * 注册 SemicolonPathFilter，优先级最高。
 * 模拟旧版 Tomcat 的 ..;/ 分号路径参数剥离行为，让穿越生效。
 */
@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<SemicolonPathFilter> semicolonPathFilter() {
        FilterRegistrationBean<SemicolonPathFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(new SemicolonPathFilter());
        registration.addUrlPatterns("/*");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }
}
