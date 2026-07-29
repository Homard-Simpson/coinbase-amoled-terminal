#include "runtime_config.h"

#include <array>
#include <cstdio>
#include <cstring>
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
constexpr char kSetupPasswordKey[] = "ap_password";
constexpr char kConfigVersionKey[] = "cfg_version";
constexpr uint8_t kConfigVersion = 1;

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

    bool dirty = false;
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
    ESP_LOGI(kTag, "runtime configuration loaded provisioned=%d", config_.IsProvisioned());
    return ESP_OK;
}

RuntimeConfigSnapshot RuntimeConfig::Snapshot() const {
    ScopedLock guard(lock_);
    return config_;
}

bool RuntimeConfig::IsProvisioned() const {
    return Snapshot().IsProvisioned();
}

esp_err_t RuntimeConfig::SaveBridge(const std::string& bridge_url,
                                    const std::string& bearer_token,
                                    std::string* validation_error) {
    std::string reason;
    if (!terminal::validation::BridgeUrl(bridge_url, &reason)) {
        if (validation_error) *validation_error = reason;
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
    if (err == ESP_OK && !bearer_token.empty())
        err = nvs_set_str(nvs, kBearerTokenKey, bearer_token.c_str());
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    if (err != ESP_OK) return err;

    config_.bridge_url = bridge_url;
    config_.bearer_token = token;
    if (validation_error) validation_error->clear();
    ESP_LOGI(kTag, "bridge configuration saved");
    return ESP_OK;
}
