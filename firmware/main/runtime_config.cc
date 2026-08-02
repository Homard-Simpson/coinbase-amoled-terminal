#include "runtime_config.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <utility>

#include "config_validation.h"
#include "esp_log.h"
#include "esp_random.h"
#include "nvs.h"

namespace {
constexpr char kTag[] = "runtime-config";
constexpr char kNamespace[] = "terminal";
constexpr char kDeviceIdKey[] = "device_id";
constexpr char kBridgeUrlKey[] = "bridge_url";
constexpr char kBearerTokenKey[] = "bridge_token";
constexpr char kPendingUrlKey[] = "pending_url";
constexpr char kPendingTokenKey[] = "pending_token";
constexpr char kPendingDeviceIdKey[] = "pending_id";
constexpr char kPendingExpiryKey[] = "pending_exp";
constexpr char kSetupPasswordKey[] = "ap_password";
constexpr char kConfigVersionKey[] = "cfg_version";
constexpr uint8_t kConfigVersion = 1;

esp_err_t ErasePending(nvs_handle_t nvs) {
    esp_err_t result = ESP_OK;
    for (const char* key : {kPendingUrlKey, kPendingTokenKey, kPendingDeviceIdKey,
                            kPendingExpiryKey}) {
        const esp_err_t err = nvs_erase_key(nvs, key);
        if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND && result == ESP_OK) result = err;
    }
    return result;
}

std::string ReadString(nvs_handle_t nvs, const char* key) {
    size_t size = 0;
    if (nvs_get_str(nvs, key, nullptr, &size) != ESP_OK || size < 2) return {};
    std::string value(size, '\0');
    if (nvs_get_str(nvs, key, value.data(), &size) != ESP_OK || size < 2) return {};
    value.resize(size - 1);  // NVS length includes the trailing null.
    return value;
}

std::string GenerateDeviceId() {
    std::array<uint8_t, 16> bytes{};
    esp_fill_random(bytes.data(), bytes.size());
    bytes[6] = static_cast<uint8_t>((bytes[6] & 0x0f) | 0x40);  // UUID v4
    bytes[8] = static_cast<uint8_t>((bytes[8] & 0x3f) | 0x80);
    char id[37];
    snprintf(id, sizeof(id),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
             bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    return id;
}

constexpr char kSetupAlphabet[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

std::string GenerateSetupPassword() {
    std::string password(12, 'A');
    for (char& c : password) c = kSetupAlphabet[esp_random() % (sizeof(kSetupAlphabet) - 1)];
    return password;
}

bool ValidSetupPassword(const std::string& value) {
    if (value.size() != 12) return false;
    for (char c : value) if (!strchr(kSetupAlphabet, c)) return false;
    return true;
}

class ScopedLock {
public:
    explicit ScopedLock(SemaphoreHandle_t lock) : lock_(lock) {
        if (lock_) xSemaphoreTake(lock_, portMAX_DELAY);
    }
    ~ScopedLock() {
        if (lock_) xSemaphoreGive(lock_);
    }
private:
    SemaphoreHandle_t lock_;
};
}  // namespace

bool RuntimeConfigSnapshot::IsProvisioned() const {
    return terminal::validation::BridgeUrl(bridge_url) &&
           terminal::validation::BearerToken(bearer_token) &&
           terminal::validation::DeviceId(device_id);
}

bool RuntimeConfigSnapshot::HasPendingProvisioning() const {
    return terminal::validation::BridgeUrl(pending_bridge_url) &&
           terminal::validation::BearerToken(pending_token) &&
           terminal::validation::DeviceId(pending_device_id) &&
           pending_expires_at > 0;
}

RuntimeConfig& RuntimeConfig::GetInstance() {
    static RuntimeConfig instance;
    return instance;
}

esp_err_t RuntimeConfig::Initialize() {
    if (!lock_) {
        lock_ = xSemaphoreCreateMutex();
        if (!lock_) return ESP_ERR_NO_MEM;
    }
    ScopedLock guard(lock_);

    nvs_handle_t nvs = 0;
    esp_err_t err = nvs_open(kNamespace, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;

    RuntimeConfigSnapshot loaded;
    loaded.device_id = ReadString(nvs, kDeviceIdKey);
    loaded.bridge_url = ReadString(nvs, kBridgeUrlKey);
    loaded.bearer_token = ReadString(nvs, kBearerTokenKey);
    loaded.setup_ap_password = ReadString(nvs, kSetupPasswordKey);
    loaded.pending_bridge_url = ReadString(nvs, kPendingUrlKey);
    loaded.pending_token = ReadString(nvs, kPendingTokenKey);
    loaded.pending_device_id = ReadString(nvs, kPendingDeviceIdKey);
    if (nvs_get_i64(nvs, kPendingExpiryKey, &loaded.pending_expires_at) != ESP_OK)
        loaded.pending_expires_at = 0;

    bool dirty = false;
    const bool any_pending = !loaded.pending_bridge_url.empty() ||
                             !loaded.pending_token.empty() ||
                             !loaded.pending_device_id.empty() ||
                             loaded.pending_expires_at != 0;
    if (any_pending && !loaded.HasPendingProvisioning()) {
        err = ErasePending(nvs);
        if (err != ESP_OK) { nvs_close(nvs); return err; }
        loaded.pending_bridge_url.clear();
        loaded.pending_token.clear();
        loaded.pending_device_id.clear();
        loaded.pending_expires_at = 0;
        dirty = true;
    }
    if (!terminal::validation::DeviceId(loaded.device_id)) {
        loaded.device_id = GenerateDeviceId();
        err = nvs_set_str(nvs, kDeviceIdKey, loaded.device_id.c_str());
        if (err != ESP_OK) { nvs_close(nvs); return err; }
        dirty = true;
    }
    if (!ValidSetupPassword(loaded.setup_ap_password)) {
        loaded.setup_ap_password = GenerateSetupPassword();
        err = nvs_set_str(nvs, kSetupPasswordKey, loaded.setup_ap_password.c_str());
        if (err != ESP_OK) { nvs_close(nvs); return err; }
        dirty = true;
    }
    uint8_t version = 0;
    if (nvs_get_u8(nvs, kConfigVersionKey, &version) != ESP_OK || version != kConfigVersion) {
        err = nvs_set_u8(nvs, kConfigVersionKey, kConfigVersion);
        if (err != ESP_OK) { nvs_close(nvs); return err; }
        dirty = true;
    }
    if (dirty) err = nvs_commit(nvs);
    nvs_close(nvs);
    if (err != ESP_OK) return err;

    config_ = std::move(loaded);
    ESP_LOGI(kTag, "runtime configuration loaded provisioned=%d pending=%d",
             config_.IsProvisioned(), config_.HasPendingProvisioning());
    return ESP_OK;
}

RuntimeConfigSnapshot RuntimeConfig::Snapshot() const {
    ScopedLock guard(lock_);
    return config_;
}

bool RuntimeConfig::IsProvisioned() const {
    return Snapshot().IsProvisioned();
}

bool RuntimeConfig::HasPendingProvisioning() const {
    return Snapshot().HasPendingProvisioning();
}

esp_err_t RuntimeConfig::SaveBridge(const std::string& bridge_url,
                                    const std::string& bearer_token,
                                    std::string* validation_error) {
    return SaveProvisioning(bridge_url, Snapshot().device_id, bearer_token,
                            validation_error);
}

esp_err_t RuntimeConfig::SaveProvisioning(const std::string& bridge_url,
                                          const std::string& device_id,
                                          const std::string& bearer_token,
                                          std::string* validation_error) {
    std::string reason;
    if (!terminal::validation::BridgeUrl(bridge_url, &reason)) {
        if (validation_error) *validation_error = reason;
        return ESP_ERR_INVALID_ARG;
    }
    if (!terminal::validation::DeviceId(device_id)) {
        if (validation_error) *validation_error = "Device ID is invalid";
        return ESP_ERR_INVALID_ARG;
    }

    ScopedLock guard(lock_);
    const std::string token = bearer_token.empty() ? config_.bearer_token : bearer_token;
    if (!terminal::validation::BearerToken(token, &reason)) {
        if (validation_error) *validation_error = bearer_token.empty()
            ? "A bridge-issued bearer token is required on first setup"
            : reason;
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t nvs = 0;
    esp_err_t err = nvs_open(kNamespace, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    err = nvs_set_str(nvs, kBridgeUrlKey, bridge_url.c_str());
    if (err == ESP_OK) err = nvs_set_str(nvs, kDeviceIdKey, device_id.c_str());
    if (err == ESP_OK && !bearer_token.empty())
        err = nvs_set_str(nvs, kBearerTokenKey, bearer_token.c_str());
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    if (err != ESP_OK) return err;

    config_.bridge_url = bridge_url;
    config_.device_id = device_id;
    config_.bearer_token = token;
    if (validation_error) validation_error->clear();
    ESP_LOGI(kTag, "bridge configuration saved");
    return ESP_OK;
}

esp_err_t RuntimeConfig::SavePendingProvisioning(
        const std::string& bridge_url, const std::string& device_id,
        const std::string& pending_token, int64_t expires_at,
        std::string* validation_error) {
    std::string reason;
    if (!terminal::validation::BridgeUrl(bridge_url, &reason)) {
        if (validation_error) *validation_error = reason;
        return ESP_ERR_INVALID_ARG;
    }
    if (!terminal::validation::DeviceId(device_id)) {
        if (validation_error) *validation_error = "Device ID is invalid";
        return ESP_ERR_INVALID_ARG;
    }
    if (!terminal::validation::BearerToken(pending_token, &reason)) {
        if (validation_error) *validation_error = reason;
        return ESP_ERR_INVALID_ARG;
    }
    if (expires_at <= 0) {
        if (validation_error) *validation_error = "Pending setup expiry is invalid";
        return ESP_ERR_INVALID_ARG;
    }

    ScopedLock guard(lock_);
    nvs_handle_t nvs = 0;
    esp_err_t err = nvs_open(kNamespace, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    err = nvs_set_str(nvs, kPendingUrlKey, bridge_url.c_str());
    if (err == ESP_OK) err = nvs_set_str(nvs, kPendingDeviceIdKey, device_id.c_str());
    if (err == ESP_OK) err = nvs_set_str(nvs, kPendingTokenKey, pending_token.c_str());
    if (err == ESP_OK) err = nvs_set_i64(nvs, kPendingExpiryKey, expires_at);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    if (err != ESP_OK) return err;

    config_.pending_bridge_url = bridge_url;
    config_.pending_device_id = device_id;
    config_.pending_token = pending_token;
    config_.pending_expires_at = expires_at;
    if (validation_error) validation_error->clear();
    ESP_LOGI(kTag, "pending bridge configuration saved");
    return ESP_OK;
}

esp_err_t RuntimeConfig::PromotePendingProvisioning() {
    ScopedLock guard(lock_);
    if (!config_.HasPendingProvisioning()) return ESP_ERR_INVALID_STATE;
    nvs_handle_t nvs = 0;
    esp_err_t err = nvs_open(kNamespace, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    err = nvs_set_str(nvs, kBridgeUrlKey, config_.pending_bridge_url.c_str());
    if (err == ESP_OK) err = nvs_set_str(nvs, kDeviceIdKey, config_.pending_device_id.c_str());
    if (err == ESP_OK) err = nvs_set_str(nvs, kBearerTokenKey, config_.pending_token.c_str());
    if (err == ESP_OK) err = ErasePending(nvs);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    if (err != ESP_OK) return err;

    config_.bridge_url = config_.pending_bridge_url;
    config_.device_id = config_.pending_device_id;
    config_.bearer_token = config_.pending_token;
    config_.pending_bridge_url.clear();
    config_.pending_device_id.clear();
    std::fill(config_.pending_token.begin(), config_.pending_token.end(), '\0');
    config_.pending_token.clear();
    config_.pending_expires_at = 0;
    ESP_LOGI(kTag, "pending bridge configuration activated");
    return ESP_OK;
}

esp_err_t RuntimeConfig::ClearPendingProvisioning() {
    ScopedLock guard(lock_);
    nvs_handle_t nvs = 0;
    esp_err_t err = nvs_open(kNamespace, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    err = ErasePending(nvs);
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    if (err != ESP_OK) return err;
    config_.pending_bridge_url.clear();
    config_.pending_device_id.clear();
    std::fill(config_.pending_token.begin(), config_.pending_token.end(), '\0');
    config_.pending_token.clear();
    config_.pending_expires_at = 0;
    ESP_LOGI(kTag, "pending bridge configuration cleared");
    return ESP_OK;
}
