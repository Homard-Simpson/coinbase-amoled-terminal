#pragma once

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace terminal::ota {

// esp_app_desc_t::version has 32 bytes, including its terminator. Keep this
// pure helper independent of ESP-IDF so descriptor and manifest boundaries are
// host-testable.
constexpr std::size_t kAppVersionCapacity = 32;
constexpr std::size_t kMaxFirmwareVersionLength = kAppVersionCapacity - 1;
constexpr std::size_t kMaxReleaseVersionLength = kMaxFirmwareVersionLength + 1;
constexpr std::size_t kMaxVersionComponentDigits = 10;
static_assert(kMaxFirmwareVersionLength + 1 == kAppVersionCapacity);

struct SemanticVersion {
    uint32_t major = 0;
    uint32_t minor = 0;
    uint32_t patch = 0;
};

inline bool BoundedCStringView(const char* value, std::size_t capacity,
                               std::string_view* result) {
    if (!value || !result || capacity == 0) return false;
    std::size_t length = 0;
    while (length < capacity && value[length] != '\0') ++length;
    if (length == capacity) return false;
    *result = std::string_view(value, length);
    return true;
}

inline bool EndsWith(std::string_view value, std::string_view suffix) {
    return value.size() >= suffix.size() &&
           value.substr(value.size() - suffix.size()) == suffix;
}

inline bool ParseStableVersion(std::string_view value, SemanticVersion* result) {
    if (!result || value.empty() || value.size() > kMaxFirmwareVersionLength)
        return false;
    SemanticVersion parsed;
    uint32_t* fields[] = {&parsed.major, &parsed.minor, &parsed.patch};
    std::size_t offset = 0;
    for (std::size_t field = 0; field < 3; ++field) {
        if (offset >= value.size() ||
            !std::isdigit(static_cast<unsigned char>(value[offset])))
            return false;
        uint64_t number = 0;
        std::size_t digits = 0;
        const std::size_t component_start = offset;
        while (offset < value.size() &&
               std::isdigit(static_cast<unsigned char>(value[offset]))) {
            number = number * 10 + static_cast<unsigned>(value[offset] - '0');
            if (number > UINT32_MAX || ++digits > kMaxVersionComponentDigits)
                return false;
            ++offset;
        }
        if (digits > 1 && value[component_start] == '0') return false;
        *fields[field] = static_cast<uint32_t>(number);
        if (field < 2) {
            if (offset >= value.size() || value[offset] != '.') return false;
            ++offset;
        }
    }
    if (offset != value.size()) return false;
    *result = parsed;
    return true;
}

inline bool ParseBoardFirmwareVersion(std::string_view value,
                                      std::string_view board_suffix,
                                      SemanticVersion* result) {
    if (value.empty() || value.size() > kMaxFirmwareVersionLength ||
        board_suffix.empty() || value.size() <= board_suffix.size() ||
        !EndsWith(value, board_suffix))
        return false;
    return ParseStableVersion(value.substr(0, value.size() - board_suffix.size()),
                              result);
}

inline bool IsNewer(const SemanticVersion& candidate,
                    const SemanticVersion& current) {
    if (candidate.major != current.major) return candidate.major > current.major;
    if (candidate.minor != current.minor) return candidate.minor > current.minor;
    return candidate.patch > current.patch;
}

}  // namespace terminal::ota
