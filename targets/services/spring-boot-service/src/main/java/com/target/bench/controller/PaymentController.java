package com.target.bench.controller;

import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/payments")
public class PaymentController {

    @GetMapping
    public List<Map<String, Object>> listPayments() {
        return List.of(
            Map.of("id", "PAY-001", "orderId", "ORD-2024-001", "method", "wechat_pay", "amount", 9999, "status", "success"),
            Map.of("id", "PAY-002", "orderId", "ORD-2024-002", "method", "alipay", "amount", 12999, "status", "success"),
            Map.of("id", "PAY-003", "orderId", "ORD-2024-003", "method", "stripe", "amount", 2999, "status", "pending")
        );
    }

    @GetMapping("/{id}")
    public Map<String, Object> getPayment(@PathVariable String id) {
        return switch (id) {
            case "PAY-001" -> Map.of(
                "id", "PAY-001", "orderId", "ORD-2024-001",
                "method", "wechat_pay", "amount", 9999, "status", "success",
                "gatewayTxnId", "wx_txn_4200001234202401010001234567",
                "paidAt", "2024-01-15T08:05:00Z"
            );
            default -> Map.of("id", id, "status", "unknown");
        };
    }
}
