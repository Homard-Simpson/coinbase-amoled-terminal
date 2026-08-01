#pragma once

#include <string>

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

struct RuntimeConfigSnapshot {
    std::string bridge_url;
    std::string bearer_token;
    std::string device_id;
    std::string setup_ap_password;

    bool IsProvisioned() const;
};

class RuntimeConfig {
public:
    static RuntimeConfig& GetInstance();

    esp_err_t Initialize();
    RuntimeConfigSnapshot Snapshot() const;
    bool IsProvisioned() const;

    // An empty token keeps the existing token. First-time setup must provide one.
    esp_err_t SaveBridge(const std::string& bridge_url, const std::string& bearer_token,
                         std::string* validation_error = nullptr);
    // USB-assisted onboarding replaces the temporary first-boot UUID with the
    // exact bridge-allowlisted UUID returned by localhost.
    esp_err_t SaveProvisioning(const std::string& bridge_url,
                               const std::string& device_id,
                               const std::string& bearer_token,
                               std::string* validation_error = nullptr);

private:
    RuntimeConfig() = default;
    RuntimeConfig(const RuntimeConfig&) = delete;
    RuntimeConfig& operator=(const RuntimeConfig&) = delete;

    mutable SemaphoreHandle_t lock_ = nullptr;
    RuntimeConfigSnapshot config_;
};
