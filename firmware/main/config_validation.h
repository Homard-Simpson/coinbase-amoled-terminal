#pragma once

#include <string>
#include <string_view>

namespace terminal::validation {

constexpr size_t kMaxBridgeUrlBytes = 255;
constexpr size_t kMinBearerTokenBytes = 20;
constexpr size_t kMaxBearerTokenBytes = 512;

bool BridgeUrl(std::string_view value, std::string* reason = nullptr);
bool BearerToken(std::string_view value, std::string* reason = nullptr);
bool WifiCredential(std::string_view ssid, std::string_view password,
                    std::string* reason = nullptr);
bool DeviceId(std::string_view value);

}  // namespace terminal::validation
