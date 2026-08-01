#pragma once

#include <cstdint>
#include <string>

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

struct OnboardingMetadataSnapshot {
    std::string session_id;
    std::string setup_token;
    std::string completion_token;
    std::string csrf_token;
    std::string endpoint_url;
    std::string endpoint_origin;
    std::string local_page_url;
    std::string bridge_url;
    int64_t expires_at = 0;

    bool IsAvailable() const;
};

class OnboardingMetadata {
public:
    static OnboardingMetadata& GetInstance();

    // Invalid, absent, or corrupt metadata fails closed as ESP_ERR_NOT_FOUND.
    esp_err_t Initialize();
    OnboardingMetadataSnapshot Snapshot() const;
    bool IsAvailable() const;

    // Erases only the dedicated onboarding partition after a successful save.
    esp_err_t Clear();

private:
    OnboardingMetadata() = default;
    OnboardingMetadata(const OnboardingMetadata&) = delete;
    OnboardingMetadata& operator=(const OnboardingMetadata&) = delete;

    mutable SemaphoreHandle_t lock_ = nullptr;
    OnboardingMetadataSnapshot metadata_;
};
