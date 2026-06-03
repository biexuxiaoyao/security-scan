// 已加密数据示例 — 配置了 encrypted_prefixes 后不应告警
package com.example.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class EncryptedConfig {

    @Value("${db.password:BEE_7x9k2m4n8q}")
    private String dbPassword;

    @Value("${api.key:ENC(abc123def456)}")
    private String apiKey;

    private String encryptedSecret = "{cipher}AQAABABZX5dX8x...";

    public String getDbPassword() {
        return dbPassword;
    }
}
