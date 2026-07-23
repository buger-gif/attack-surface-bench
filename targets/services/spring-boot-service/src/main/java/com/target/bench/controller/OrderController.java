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
}
