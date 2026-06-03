// 安全示例 — 不应触发告警
package com.example.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class SafeConfig {

    @Value("${feature.enabled:true}")
    private boolean featureEnabled;

    @Value("${max.retry:3}")
    private int maxRetry;

    @Value("${mode:DEV}")
    private String mode;

    @Value("${server.port:8080}")
    private int port;

    public String getMode() {
        return mode;
    }
}
