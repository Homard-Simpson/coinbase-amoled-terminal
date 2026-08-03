#include "auto_ota_v2.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "cJSON.h"
#include "esp_app_desc.h"
#include "esp_app_format.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_random.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/sha256.h"
#include "network_portal.h"
#include "ota_coordination.h"
#include "ota_version_policy.h"
#include "runtime_config.h"
#include "sodium.h"

namespace {
constexpr char kTag[] = "auto-ota-v2";
constexpr char kManifestUrl[] =
    "https://github.com/Homard-Simpson/coinbase-amoled-terminal/releases/latest/download/"
    "firmware-manifest.json";
constexpr char kSignatureUrl[] =
    "https://github.com/Homard-Simpson/coinbase-amoled-terminal/releases/latest/download/"
    "firmware-manifest.json.sig";
constexpr char kArtifactPrefix[] =
    "https://github.com/Homard-Simpson/coinbase-amoled-terminal/releases/latest/download/";
constexpr char kSourceRepository[] =
    "https://github.com/Homard-Simpson/coinbase-amoled-terminal";
constexpr char kReleaseKeyId[] = "coinbase-amoled-release-2026-01";
constexpr char kProjectName[] = "coinbase_amoled_terminal";
constexpr char kBoardSuffix[] = "-v2";
constexpr size_t kMaxManifestBytes = 256 * 1024;
constexpr size_t kMaxSignatureBytes = 2 * 1024;
constexpr size_t kMaxApplicationBytes = 7 * 1024 * 1024;
constexpr uint32_t kInitialDelaySeconds = 60;
constexpr uint32_t kInitialJitterSeconds = 240;
constexpr uint32_t kCheckIntervalSeconds = 6 * 60 * 60;
constexpr uint32_t kRetrySeconds = 15 * 60;
constexpr std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> kReleasePublicKey = {
    0x30, 0xbd, 0xa9, 0x9f, 0x00, 0xe1, 0x71, 0x7c,
    0x75, 0x06, 0x8f, 0xd3, 0x23, 0x43, 0xb0, 0x1f,
    0x96, 0x1b, 0x32, 0xd2, 0x52, 0xb2, 0x7e, 0x34,
    0xfc, 0xe3, 0xd2, 0x7f, 0x4b, 0x40, 0x4f, 0xf2,
};

using terminal::ota::SemanticVersion;

struct HttpBody {
    std::vector<char> bytes;
    size_t maximum = 0;
    bool overflow = false;
};

struct UpdateCandidate {
    SemanticVersion semantic_version;
    std::string firmware_version;
    std::string artifact_path;
    size_t artifact_size = 0;
    std::array<uint8_t, 32> artifact_sha256{};
};

bool ConstantTimeEqual(const uint8_t* left, const uint8_t* right, size_t size) {
    return sodium_memcmp(left, right, size) == 0;
}

bool ParseFirmwareVersion(std::string_view value, SemanticVersion* result) {
    return terminal::ota::ParseBoardFirmwareVersion(value, kBoardSuffix, result);
}

bool DecodeHexSha256(const char* value, std::array<uint8_t, 32>* output) {
    if (!value || !output || strlen(value) != 64) return false;
    for (size_t i = 0; i < output->size(); ++i) {
        unsigned byte = 0;
        if (sscanf(value + i * 2, "%2x", &byte) != 1) return false;
        (*output)[i] = static_cast<uint8_t>(byte);
    }
    for (char c : std::string_view(value, 64))
        if (!std::isdigit(static_cast<unsigned char>(c)) && !(c >= 'a' && c <= 'f'))
            return false;
    return true;
}

bool SafeArtifactName(std::string_view path) {
    if (path.empty() || path.size() > 160 || path.find('/') != std::string_view::npos ||
        path.find("..") != std::string_view::npos ||
        !terminal::ota::EndsWith(path, "-v2-application.bin"))
        return false;
    for (char c : path) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '_' && c != '-')
            return false;
    }
    return true;
}

int CountNamed(cJSON* object, const char* name, cJSON** found = nullptr) {
    int count = 0;
    if (found) *found = nullptr;
    for (cJSON* item = cJSON_IsObject(object) ? object->child : nullptr; item; item = item->next) {
        if (item->string && strcmp(item->string, name) == 0) {
            ++count;
            if (found) *found = item;
        }
    }
    return count;
}

bool UniqueString(cJSON* object, const char* name, const char** value) {
    cJSON* item = nullptr;
    if (CountNamed(object, name, &item) != 1 || !cJSON_IsString(item) || !item->valuestring)
        return false;
    *value = item->valuestring;
    return true;
}

bool UniqueTrue(cJSON* object, const char* name) {
    cJSON* item = nullptr;
    return CountNamed(object, name, &item) == 1 && cJSON_IsTrue(item);
}

bool UniqueNumber(cJSON* object, const char* name, double* value) {
    cJSON* item = nullptr;
    if (CountNamed(object, name, &item) != 1 || !cJSON_IsNumber(item)) return false;
    *value = item->valuedouble;
    return true;
}

esp_err_t BodyEvent(esp_http_client_event_t* event) {
    auto* body = static_cast<HttpBody*>(event->user_data);
    if (event->event_id == HTTP_EVENT_ON_DATA && event->data_len > 0) {
        if (body->bytes.size() + static_cast<size_t>(event->data_len) > body->maximum) {
            body->overflow = true;
            return ESP_FAIL;
        }
        const char* begin = static_cast<const char*>(event->data);
        body->bytes.insert(body->bytes.end(), begin, begin + event->data_len);
    }
    return ESP_OK;
}

bool GetSmallHttps(const char* url, size_t maximum, std::vector<char>* output) {
    HttpBody body;
    body.maximum = maximum;
    esp_http_client_config_t config{};
    config.url = url;
    config.event_handler = BodyEvent;
    config.user_data = &body;
    config.crt_bundle_attach = esp_crt_bundle_attach;
    config.timeout_ms = 15000;
    config.disable_auto_redirect = false;
    config.max_redirection_count = 5;
    config.user_agent = "amoled-terminal-v2-ota/1";
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) return false;
    esp_http_client_set_header(client, "Accept", "application/json,application/octet-stream");
    const esp_err_t err = esp_http_client_perform(client);
    const int status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);
    if (err != ESP_OK || status != 200 || body.overflow || body.bytes.empty()) return false;
    *output = std::move(body.bytes);
    return true;
}

bool VerifySignedManifest(const std::vector<char>& manifest,
                          const std::vector<char>& envelope) {
    std::vector<char> parsed_envelope(envelope);
    parsed_envelope.push_back('\0');
    cJSON* root = cJSON_ParseWithLengthOpts(parsed_envelope.data(), parsed_envelope.size(),
                                            nullptr, true);
    if (!cJSON_IsObject(root) || cJSON_GetArraySize(root) != 5) {
        if (root) cJSON_Delete(root);
        return false;
    }
    const char* algorithm = nullptr;
    const char* key_id = nullptr;
    const char* digest_hex = nullptr;
    const char* signature_text = nullptr;
    cJSON* schema = nullptr;
    const bool shape = CountNamed(root, "schema_version", &schema) == 1 &&
        cJSON_IsNumber(schema) && schema->valuedouble == 1 &&
        UniqueString(root, "algorithm", &algorithm) && strcmp(algorithm, "Ed25519") == 0 &&
        UniqueString(root, "key_id", &key_id) && strcmp(key_id, kReleaseKeyId) == 0 &&
        UniqueString(root, "manifest_sha256", &digest_hex) &&
        UniqueString(root, "signature", &signature_text);
    if (!shape) {
        cJSON_Delete(root);
        return false;
    }
    std::array<uint8_t, 32> expected_digest{};
    if (!DecodeHexSha256(digest_hex, &expected_digest)) {
        cJSON_Delete(root);
        return false;
    }
    std::array<uint8_t, 32> actual_digest{};
    if (mbedtls_sha256(reinterpret_cast<const unsigned char*>(manifest.data()), manifest.size(),
                       actual_digest.data(), 0) != 0 ||
        !ConstantTimeEqual(expected_digest.data(), actual_digest.data(), actual_digest.size())) {
        cJSON_Delete(root);
        return false;
    }
    std::array<unsigned char, crypto_sign_BYTES> signature{};
    size_t signature_size = 0;
    const int decode = sodium_base642bin(
        signature.data(), signature.size(), signature_text, strlen(signature_text),
        nullptr, &signature_size, nullptr, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    const bool verified = decode == 0 && signature_size == signature.size() &&
        crypto_sign_verify_detached(
            signature.data(), reinterpret_cast<const unsigned char*>(manifest.data()),
            manifest.size(), kReleasePublicKey.data()) == 0;
    sodium_memzero(signature.data(), signature.size());
    cJSON_Delete(root);
    return verified;
}

bool ParseCandidate(const std::vector<char>& bytes, UpdateCandidate* candidate) {
    std::vector<char> input(bytes);
    input.push_back('\0');
    cJSON* root = cJSON_ParseWithLengthOpts(input.data(), input.size(), nullptr, true);
    if (!cJSON_IsObject(root)) {
        if (root) cJSON_Delete(root);
        return false;
    }
    cJSON* schema = nullptr;
    cJSON* evidence = nullptr;
    cJSON* source = nullptr;
    cJSON* variants = nullptr;
    const char* release_version = nullptr;
    bool valid = CountNamed(root, "schema_version", &schema) == 1 && cJSON_IsNumber(schema) &&
        schema->valuedouble == 2 && UniqueString(root, "release_version", &release_version) &&
        CountNamed(root, "release_evidence", &evidence) == 1 && cJSON_IsObject(evidence) &&
        CountNamed(root, "source", &source) == 1 && cJSON_IsObject(source) &&
        CountNamed(root, "variants", &variants) == 1 && cJSON_IsObject(variants);
    if (!valid) {
        cJSON_Delete(root);
        return false;
    }

    const char* repository = nullptr;
    const char* trust_blocker = nullptr;
    cJSON* attested = nullptr;
    valid = UniqueTrue(evidence, "production_ready") &&
        UniqueTrue(evidence, "controls_verified") &&
        UniqueTrue(evidence, "client_signature_verified") &&
        CountNamed(evidence, "hardware_attested", &attested) == 1 &&
        cJSON_IsObject(attested) && UniqueTrue(attested, "v2") &&
        UniqueString(evidence, "trust_blocker", &trust_blocker) && trust_blocker[0] == '\0' &&
        UniqueString(source, "repository", &repository) &&
        strcmp(repository, kSourceRepository) == 0;
    if (!valid) {
        cJSON_Delete(root);
        return false;
    }

    cJSON* v2 = nullptr;
    cJSON* artifacts = nullptr;
    const char* board = nullptr;
    const char* firmware_version = nullptr;
    valid = CountNamed(variants, "v2", &v2) == 1 && cJSON_IsObject(v2) &&
        UniqueString(v2, "board_revision", &board) && strcmp(board, "v2") == 0 &&
        UniqueString(v2, "firmware_version", &firmware_version) &&
        CountNamed(v2, "artifacts", &artifacts) == 1 && cJSON_IsArray(artifacts);
    SemanticVersion version;
    std::string_view release;
    std::string_view firmware;
    if (!valid ||
        !terminal::ota::BoundedCStringView(
            release_version, terminal::ota::kMaxReleaseVersionLength + 1, &release) ||
        release.empty() ||
        !terminal::ota::BoundedCStringView(
            firmware_version, terminal::ota::kAppVersionCapacity, &firmware) ||
        !ParseFirmwareVersion(firmware, &version)) {
        cJSON_Delete(root);
        return false;
    }
    const std::string expected_release =
        "v" + std::string(firmware.substr(0, firmware.size() - strlen(kBoardSuffix)));
    if (expected_release != release) {
        cJSON_Delete(root);
        return false;
    }

    int applications = 0;
    UpdateCandidate parsed;
    parsed.semantic_version = version;
    parsed.firmware_version = firmware;
    cJSON* artifact = nullptr;
    cJSON_ArrayForEach(artifact, artifacts) {
        if (!cJSON_IsObject(artifact)) continue;
        const char* role = nullptr;
        if (!UniqueString(artifact, "role", &role) || strcmp(role, "application") != 0) continue;
        ++applications;
        const char* path = nullptr;
        const char* digest = nullptr;
        double offset = 0;
        double size = 0;
        if (!UniqueString(artifact, "path", &path) || !SafeArtifactName(path) ||
            !UniqueString(artifact, "sha256", &digest) ||
            !UniqueNumber(artifact, "offset", &offset) || offset != 0x20000 ||
            !UniqueNumber(artifact, "size", &size) || size < 1024 ||
            size > kMaxApplicationBytes || size != static_cast<size_t>(size) ||
            !DecodeHexSha256(digest, &parsed.artifact_sha256)) {
            cJSON_Delete(root);
            return false;
        }
        parsed.artifact_path = path;
        parsed.artifact_size = static_cast<size_t>(size);
    }
    cJSON_Delete(root);
    if (applications != 1 || parsed.artifact_path.empty()) return false;
    *candidate = std::move(parsed);
    return true;
}

struct OtaDownload {
    const UpdateCandidate* candidate = nullptr;
    const esp_partition_t* partition = nullptr;
    esp_ota_handle_t handle = 0;
    mbedtls_sha256_context sha{};
    std::vector<uint8_t> prefix;
    size_t total = 0;
    bool began = false;
    bool failed = false;
    bool sha_started = false;
};

bool ValidateImageHeader(const std::vector<uint8_t>& prefix,
                         const UpdateCandidate& candidate) {
    constexpr size_t descriptor_offset = sizeof(esp_image_header_t) +
                                         sizeof(esp_image_segment_header_t);
    if (prefix.size() < descriptor_offset + sizeof(esp_app_desc_t)) return false;
    const auto* image = reinterpret_cast<const esp_image_header_t*>(prefix.data());
    const auto* descriptor = reinterpret_cast<const esp_app_desc_t*>(
        prefix.data() + descriptor_offset);
    std::string_view project;
    std::string_view version;
    SemanticVersion parsed;
    return image->magic == ESP_IMAGE_HEADER_MAGIC &&
           descriptor->magic_word == ESP_APP_DESC_MAGIC_WORD &&
           terminal::ota::BoundedCStringView(
               descriptor->project_name, sizeof(descriptor->project_name), &project) &&
           project == kProjectName &&
           terminal::ota::BoundedCStringView(
               descriptor->version, sizeof(descriptor->version), &version) &&
           version == candidate.firmware_version &&
           ParseFirmwareVersion(version, &parsed);
}

esp_err_t OtaEvent(esp_http_client_event_t* event) {
    auto* download = static_cast<OtaDownload*>(event->user_data);
    if (event->event_id != HTTP_EVENT_ON_DATA || event->data_len <= 0 || download->failed)
        return download->failed ? ESP_FAIL : ESP_OK;
    const auto* data = static_cast<const uint8_t*>(event->data);
    size_t size = static_cast<size_t>(event->data_len);
    if (download->total + download->prefix.size() + size >
        download->candidate->artifact_size) {
        download->failed = true;
        return ESP_FAIL;
    }
    if (!download->began) {
        constexpr size_t required = sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) +
                                    sizeof(esp_app_desc_t);
        const size_t needed = required > download->prefix.size() ? required - download->prefix.size() : 0;
        const size_t take = std::min(needed, size);
        download->prefix.insert(download->prefix.end(), data, data + take);
        data += take;
        size -= take;
        if (download->prefix.size() < required) return ESP_OK;
        if (!ValidateImageHeader(download->prefix, *download->candidate)) {
            download->failed = true;
            return ESP_FAIL;
        }
        if (esp_ota_begin(download->partition, download->candidate->artifact_size,
                          &download->handle) != ESP_OK) {
            download->failed = true;
            return ESP_FAIL;
        }
        download->began = true;
        if (mbedtls_sha256_starts(&download->sha, 0) != 0) {
            download->failed = true;
            return ESP_FAIL;
        }
        download->sha_started = true;
        if (esp_ota_write(download->handle, download->prefix.data(), download->prefix.size()) != ESP_OK ||
            mbedtls_sha256_update(&download->sha, download->prefix.data(),
                                  download->prefix.size()) != 0) {
            download->failed = true;
            return ESP_FAIL;
        }
        download->total = download->prefix.size();
        download->prefix.clear();
    }
    if (size > 0) {
        if (esp_ota_write(download->handle, data, size) != ESP_OK ||
            mbedtls_sha256_update(&download->sha, data, size) != 0) {
            download->failed = true;
            return ESP_FAIL;
        }
        download->total += size;
    }
    return ESP_OK;
}

bool DownloadAndInstall(const UpdateCandidate& candidate) {
    auto& portal = NetworkPortal::GetInstance();
    if (!portal.IsConnected() || portal.IsPortalActive() || portal.IsOtaArmed()) return false;
    const esp_partition_t* partition = esp_ota_get_next_update_partition(nullptr);
    if (!partition || candidate.artifact_size > partition->size) return false;

    OtaDownload download;
    download.candidate = &candidate;
    download.partition = partition;
    mbedtls_sha256_init(&download.sha);
    std::string url = std::string(kArtifactPrefix) + candidate.artifact_path;
    esp_http_client_config_t config{};
    config.url = url.c_str();
    config.event_handler = OtaEvent;
    config.user_data = &download;
    config.crt_bundle_attach = esp_crt_bundle_attach;
    config.timeout_ms = 30000;
    config.disable_auto_redirect = false;
    config.max_redirection_count = 5;
    config.user_agent = "amoled-terminal-v2-ota/1";
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        mbedtls_sha256_free(&download.sha);
        return false;
    }
    esp_http_client_set_header(client, "Accept", "application/octet-stream");
    const esp_err_t transfer = esp_http_client_perform(client);
    const int status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    bool success = transfer == ESP_OK && status == 200 && download.began && !download.failed &&
                   download.total == candidate.artifact_size;
    std::array<uint8_t, 32> digest{};
    if (success && mbedtls_sha256_finish(&download.sha, digest.data()) != 0) success = false;
    if (success && !ConstantTimeEqual(digest.data(), candidate.artifact_sha256.data(), digest.size()))
        success = false;
    if (success && (!portal.IsConnected() || portal.IsPortalActive() || portal.IsOtaArmed()))
        success = false;
    if (success && esp_ota_end(download.handle) != ESP_OK) success = false;
    else if (!success && download.began) esp_ota_abort(download.handle);
    if (success && esp_ota_set_boot_partition(partition) != ESP_OK) success = false;
    sodium_memzero(digest.data(), digest.size());
    mbedtls_sha256_free(&download.sha);
    return success;
}

bool CheckForUpdate() {
    const esp_app_desc_t* running = esp_app_get_description();
    SemanticVersion current;
    std::string_view running_project;
    std::string_view running_version;
    if (!running ||
        !terminal::ota::BoundedCStringView(
            running->project_name, sizeof(running->project_name), &running_project) ||
        running_project != kProjectName ||
        !terminal::ota::BoundedCStringView(
            running->version, sizeof(running->version), &running_version) ||
        !ParseFirmwareVersion(running_version, &current)) {
        ESP_LOGE(kTag, "running firmware identity is not eligible for automatic OTA");
        return false;
    }

    std::vector<char> manifest;
    std::vector<char> signature;
    if (!GetSmallHttps(kManifestUrl, kMaxManifestBytes, &manifest) ||
        !GetSmallHttps(kSignatureUrl, kMaxSignatureBytes, &signature)) {
        ESP_LOGW(kTag, "release metadata unavailable; keeping current firmware");
        return false;
    }
    if (!VerifySignedManifest(manifest, signature)) {
        ESP_LOGE(kTag, "release manifest authentication failed; keeping current firmware");
        return false;
    }
    UpdateCandidate candidate;
    if (!ParseCandidate(manifest, &candidate)) {
        ESP_LOGE(kTag, "release manifest is not production-ready for V2");
        return false;
    }
    if (!terminal::ota::IsNewer(candidate.semantic_version, current)) {
        ESP_LOGI(kTag, "no strictly newer stable V2 firmware is available");
        return true;
    }
    ESP_LOGI(kTag, "installing authenticated forward V2 update version=%s",
             candidate.firmware_version.c_str());
    if (!DownloadAndInstall(candidate)) {
        ESP_LOGE(kTag, "automatic OTA failed; current slot remains selected");
        return false;
    }
    ESP_LOGI(kTag, "automatic OTA verified; restarting into rollback-protected slot");
    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();
    return true;
}

void AutomaticOtaTask(void*) {
    const uint32_t initial = kInitialDelaySeconds + esp_random() % (kInitialJitterSeconds + 1);
    vTaskDelay(pdMS_TO_TICKS(initial * 1000));
    while (true) {
        bool checked = false;
        {
            FirmwareUpdateGuard update_guard(1000);
            if (update_guard) {
                auto& portal = NetworkPortal::GetInstance();
                const bool eligible = portal.IsConnected() && !portal.IsPortalActive() &&
                                      !portal.IsOtaArmed() && !portal.IsOtaBusy() &&
                                      RuntimeConfig::GetInstance().IsProvisioned();
                checked = eligible && CheckForUpdate();
            }
        }
        const uint32_t delay = checked ? kCheckIntervalSeconds : kRetrySeconds;
        vTaskDelay(pdMS_TO_TICKS(delay * 1000));
    }
}
}  // namespace

void StartV2AutomaticOta() {
    if (sodium_init() < 0) {
        ESP_LOGE(kTag, "cryptographic self-initialization failed; automatic OTA disabled");
        return;
    }
    if (xTaskCreate(AutomaticOtaTask, "auto_ota_v2", 12288, nullptr, 3, nullptr) != pdPASS)
        ESP_LOGE(kTag, "unable to start automatic OTA task");
}
