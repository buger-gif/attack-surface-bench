package com.target.bench.controller;

import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    @GetMapping
    public List<Map<String, Object>> listOrders() {
        return List.of(
            Map.of("id", "ORD-2024-001", "userId", 1, "item", "Server Rack", "amount", 9999, "status", "completed"),
            Map.of("id", "ORD-2024-002", "userId", 2, "item", "MacBook Pro", "amount", 12999, "status", "shipped"),
            Map.of("id", "ORD-2024-003", "userId", 3, "item", "Dell Monitor", "amount", 2999, "status", "pending")
        );
    }

    @GetMapping("/{id}")
    public Map<String, Object> getOrder(@PathVariable String id) {
        return switch (id) {
            case "ORD-2024-001" -> Map.of(
                "id", "ORD-2024-001", "userId", 1, "item", "Server Rack",
                "amount", 9999, "status", "completed",
                "shippingAddress", "北京市朝阳区建国路88号",
                "trackingNumber", "SF1234567890"
            );
            default -> Map.of("id", id, "status", "unknown");
        };
    }

    @GetMapping("/admin/dashboard")
    public Map<String, Object> adminDashboard() {
        return Map.of(
            "dashboard", "order_management",
            "flag", "ADMIN_WHITELIST_BYPASS_ORDER",
            "allOrders", List.of(
                Map.of("id", "ORD-2024-001", "userId", 1, "amount", 9999,
                       "shippingAddress", "北京市朝阳区建国路88号", "status", "completed"),
                Map.of("id", "ORD-2024-002", "userId", 2, "amount", 12999,
                       "shippingAddress", "上海市浦东新区陆家嘴环路1000号", "status", "shipped")
            ),
            "internalConfig", Map.of(
                "mqUrl", System.getenv().getOrDefault("MQ_URL", "N/A"),
                "mqUsername", System.getenv().getOrDefault("MQ_USERNAME", "N/A"),
                "mqPassword", System.getenv().getOrDefault("MQ_PASSWORD", "N/A"),
                "dbPassword", System.getenv().getOrDefault("DB_PASSWORD", "N/A")
            )
        );
    }
}
