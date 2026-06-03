// 不安全示例 — 应触发告警
package com.example.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class UnsafeConfig {

    @Value("${db.password:password123}")
    private String dbPassword;

    private String secretKey = "sk-abcdefghijklmnopqrstuvwxyz";

    private String apiToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";

    public String getDbPassword() {
        return dbPassword;
    }
}
