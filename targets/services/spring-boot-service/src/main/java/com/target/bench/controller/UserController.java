package com.target.bench.controller;

import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping
    public List<Map<String, Object>> listUsers() {
        return List.of(
            Map.of("id", 1, "username", "admin", "role", "admin",
                   "email", "admin@target.bench", "phone", "138****8888"),
            Map.of("id", 2, "username", "zhangsan", "role", "user",
                   "email", "zhangsan@target.bench", "phone", "139****9999"),
            Map.of("id", 3, "username", "lisi", "role", "user",
                   "email", "lisi@target.bench", "phone", "137****0000")
        );
    }

    @GetMapping("/{id}")
    public Map<String, Object> getUser(@PathVariable Long id) {
        if (id == 1) {
            return Map.of("id", 1, "username", "admin", "role", "admin",
                "email", "admin@target.bench", "createdAt", "2024-01-15T08:00:00Z");
        }
        return Map.of("id", id, "username", "user_" + id, "role", "user");
    }

    @GetMapping("/admin/dashboard")
    public Map<String, Object> adminDashboard() {
        return Map.of(
            "dashboard", "user_management",
            "flag", "ADMIN_WHITELIST_BYPASS_USER",
            "allUsers", List.of(
                Map.of("id", 1, "username", "admin", "email", "admin@target.bench",
                       "role", "admin", "password_hash", "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJYd0IqXrO"),
                Map.of("id", 2, "username", "zhangsan", "email", "zhangsan@target.bench",
                       "role", "user", "password_hash", "$2a$10$dXJ3SW6G7P50lGmMQgel3uGqSj6e3q2S1d3Xd3e3q2S1d3Xd3e3q"),
                Map.of("id", 3, "username", "lisi", "email", "lisi@target.bench",
                       "role", "user", "password_hash", "$2a$10$hXJ3SW6G7P50lGmMQgel3uGqSj6e3q2S1d3Xd3e3q2S1d3Xd3e3q")
            ),
            "internalConfig", Map.of(
                "authMode", "JWT",
                "jwtSecret", System.getenv().getOrDefault("JWT_SECRET", "N/A"),
                "dbUrl", System.getenv().getOrDefault("DB_URL", "N/A"),
                "dbPassword", System.getenv().getOrDefault("DB_PASSWORD", "N/A"),
                "redisPassword", System.getenv().getOrDefault("REDIS_PASSWORD", "N/A")
            )
        );
    }
}
