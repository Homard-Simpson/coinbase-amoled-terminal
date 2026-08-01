#include "onboarding_metadata.h"

#include <array>
#include <cmath>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#include "cJSON.h"
#include "config_validation.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "mbedtls/sha256.h"

namespace {
constexpr char kTag[] = "onboarding-metadata";
constexpr uint8_t kSubtype = 0x40;
constexpr char kPartitionLabel[] = "onboarding";
constexpr std::array<uint8_t, 8> kMagic = {'C', 'B', 'A', 'T', 'S', 'T', '0', '1'};
constexpr size_t kHeaderBytes = 48;
constexpr size_t kMaxPayloadBytes = 4096;

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

uint32_t ReadLe32(const uint8_t* value) {
    return static_cast<uint32_t>(value[0]) |
           (static_cast<uint32_t>(value[1]) << 8) |
           (static_cast<uint32_t>(value[2]) << 16) |
           (static_cast<uint32_t>(value[3]) << 24);
}

bool ConstantTimeEqual(const uint8_t* left, const uint8_t* right, size_t length) {
    uint8_t difference = 0;
    for (size_t i = 0; i < length; ++i) difference |= left[i] ^ right[i];
    return difference == 0;
}

bool OpaqueValue(std::string_view value) {
    if (value.size() < 20 || value.size() > 128) return false;
    for (char character : value) {
        const bool allowed = (character >= 'a' && character <= 'z') ||
                             (character >= 'A' && character <= 'Z') ||
                             (character >= '0' && character <= '9') ||
                             character == '_' || character == '-';
        if (!allowed) return false;
    }
    return true;
}

bool LoopbackUrl(std::string_view value, std::string_view required_path,
                 std::string* origin) {
    constexpr std::string_view prefix = "http://127.0.0.1:";
    if (value.rfind(prefix, 0) != 0 || value.size() > 255) return false;
    const size_t path_at = value.find('/', prefix.size());
    if (path_at == std::string_view::npos || value.substr(path_at) != required_path)
        return false;
    const std::string_view port = value.substr(prefix.size(), path_at - prefix.size());
    if (port.empty() || port.size() > 5) return false;
    unsigned parsed_port = 0;
    for (char character : port) {
        if (character < '0' || character > '9') return false;
        parsed_port = parsed_port * 10 + static_cast<unsigned>(character - '0');
    }
    if (parsed_port == 0 || parsed_port > 65535) return false;
    if (origin) *origin = std::string(value.substr(0, path_at));
    return true;
}

cJSON* UniqueField(cJSON* root, const char* name) {
    cJSON* found = nullptr;
    int matches = 0;
    for (cJSON* item = root ? root->child : nullptr; item; item = item->next) {
        if (item->string && std::strcmp(item->string, name) == 0) {
            found = item;
            ++matches;
        }
    }
    return matches == 1 ? found : nullptr;
}

bool JsonString(cJSON* root, const char* name, std::string* output) {
    cJSON* item = UniqueField(root, name);
    if (!cJSON_IsString(item) || !item->valuestring) return false;
    *output = item->valuestring;
    return true;
}

bool ParsePayload(const char* payload, size_t length,
                  OnboardingMetadataSnapshot* metadata) {
    const char* parse_end = nullptr;
    cJSON* root = cJSON_ParseWithLengthOpts(payload, length, &parse_end, false);
    if (!cJSON_IsObject(root) || parse_end != payload + length) {
        if (root) cJSON_Delete(root);
        return false;
    }
    int fields = 0;
    for (cJSON* item = root->child; item; item = item->next) ++fields;
    cJSON* schema = UniqueField(root, "schema_version");
    cJSON* expiry = UniqueField(root, "expires_at");
    bool valid = fields == 8 && cJSON_IsNumber(schema) && schema->valuedouble == 1 &&
                 cJSON_IsNumber(expiry) && std::isfinite(expiry->valuedouble) &&
                 expiry->valuedouble > 0 &&
                 expiry->valuedouble <=
                     static_cast<double>(std::numeric_limits<int64_t>::max()) &&
                 JsonString(root, "session_id", &metadata->session_id) &&
                 JsonString(root, "setup_token", &metadata->setup_token) &&
                 JsonString(root, "csrf_token", &metadata->csrf_token) &&
                 JsonString(root, "endpoint_url", &metadata->endpoint_url) &&
                 JsonString(root, "local_page_url", &metadata->local_page_url) &&
                 JsonString(root, "bridge_url", &metadata->bridge_url);
    if (valid) {
        metadata->expires_at = static_cast<int64_t>(expiry->valuedouble);
        const std::string local_path = "/setup/" + metadata->session_id;
        std::string endpoint_origin;
        std::string local_origin;
        valid = OpaqueValue(metadata->session_id) &&
                OpaqueValue(metadata->setup_token) &&
                OpaqueValue(metadata->csrf_token) &&
                LoopbackUrl(metadata->endpoint_url, "/v1/onboarding", &endpoint_origin) &&
                LoopbackUrl(metadata->local_page_url, local_path, &local_origin) &&
                endpoint_origin == local_origin &&
                terminal::validation::BridgeUrl(metadata->bridge_url);
        metadata->endpoint_origin = endpoint_origin;
    }
    cJSON_Delete(root);
    return valid;
}

const esp_partition_t* FindPartition() {
    return esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA,
        static_cast<esp_partition_subtype_t>(kSubtype),
        kPartitionLabel);
}
}  // namespace

bool OnboardingMetadataSnapshot::IsAvailable() const {
    return !session_id.empty() && !setup_token.empty() && !csrf_token.empty() &&
           !endpoint_url.empty() && !local_page_url.empty() && !bridge_url.empty();
}

OnboardingMetadata& OnboardingMetadata::GetInstance() {
    static OnboardingMetadata instance;
    return instance;
}

esp_err_t OnboardingMetadata::Initialize() {
    if (!lock_) {
        lock_ = xSemaphoreCreateMutex();
        if (!lock_) return ESP_ERR_NO_MEM;
    }
    ScopedLock guard(lock_);
    metadata_ = {};
    const esp_partition_t* partition = FindPartition();
    if (!partition || partition->size < kHeaderBytes) return ESP_ERR_NOT_FOUND;

    std::array<uint8_t, kHeaderBytes> header{};
    esp_err_t error = esp_partition_read(partition, 0, header.data(), header.size());
    if (error != ESP_OK) return error;
    if (!ConstantTimeEqual(header.data(), kMagic.data(), kMagic.size()) ||
        ReadLe32(header.data() + 8) != 1) {
        return ESP_ERR_NOT_FOUND;
    }
    const uint32_t length = ReadLe32(header.data() + 12);
    if (length == 0 || length > kMaxPayloadBytes || kHeaderBytes + length > partition->size)
        return ESP_ERR_NOT_FOUND;

    std::vector<char> payload(length + 1, '\0');
    error = esp_partition_read(partition, kHeaderBytes, payload.data(), length);
    if (error != ESP_OK) return error;
    std::array<uint8_t, 32> digest{};
    if (mbedtls_sha256(reinterpret_cast<const unsigned char*>(payload.data()),
                       length, digest.data(), 0) != 0 ||
        !ConstantTimeEqual(digest.data(), header.data() + 16, digest.size())) {
        return ESP_ERR_NOT_FOUND;
    }

    OnboardingMetadataSnapshot parsed;
    if (!ParsePayload(payload.data(), length, &parsed)) return ESP_ERR_NOT_FOUND;
    metadata_ = std::move(parsed);
    ESP_LOGI(kTag, "valid one-time USB setup metadata loaded");
    return ESP_OK;
}

OnboardingMetadataSnapshot OnboardingMetadata::Snapshot() const {
    ScopedLock guard(lock_);
    return metadata_;
}

bool OnboardingMetadata::IsAvailable() const {
    return Snapshot().IsAvailable();
}

esp_err_t OnboardingMetadata::Clear() {
    ScopedLock guard(lock_);
    const esp_partition_t* partition = FindPartition();
    if (!partition) return ESP_ERR_NOT_FOUND;
    const esp_err_t error = esp_partition_erase_range(partition, 0, partition->size);
    if (error == ESP_OK) {
        metadata_ = {};
        ESP_LOGI(kTag, "one-time USB setup metadata cleared");
    }
    return error;
}
