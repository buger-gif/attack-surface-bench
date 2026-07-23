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
}
