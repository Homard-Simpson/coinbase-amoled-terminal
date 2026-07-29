#pragma once

#include <atomic>
#include <functional>
#include <string>

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

class NetworkPortal {
public:
    static NetworkPortal& GetInstance();

    void Initialize(std::function<void(bool)> connection_callback,
                    std::function<void()> state_callback);
    void ArmOta();
    esp_err_t SaveCredential(const std::string& ssid, const std::string& password);

    bool IsConnected() const { return connected_.load(); }
    bool IsPortalActive() const { return portal_active_.load(); }
    bool IsOtaArmed() const { return ota_armed_.load(); }
    bool HasSavedNetwork() const;
    std::string GetApSsid() const;
    std::string GetApPassword() const;
    std::string GetOtaCode() const;
    std::string GetCsrfToken() const;

private:
    NetworkPortal() = default;
    NetworkPortal(const NetworkPortal&) = delete;
    NetworkPortal& operator=(const NetworkPortal&) = delete;

    void StartPortal();
    void StopPortal();
    void LoadCredentials();
    void ApplyCredential(size_t index);
    void NotifyState();

    static void EventHandler(void* arg, const char* event_base, int32_t event_id,
                             void* event_data);
    static void ConnectionTimeout(void* arg);
    static void OtaTimeout(void* arg);
    static void ClosePortalTask(void* arg);

    std::function<void(bool)> connection_callback_;
    std::function<void()> state_callback_;
    std::atomic_bool connected_{false};
    std::atomic_bool portal_active_{false};
    std::atomic_bool ota_armed_{false};
    size_t credential_index_ = 0;
    mutable SemaphoreHandle_t state_lock_ = nullptr;
    std::string ap_ssid_;
    std::string ap_password_;
    std::string ota_code_;
    std::string csrf_token_;
};
