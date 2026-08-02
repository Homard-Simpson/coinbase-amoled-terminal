#include <cstdlib>
#include <iostream>
#include <string>

#include "config_validation.h"

namespace {
void Check(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}
}  // namespace

int main() {
    using terminal::validation::BearerToken;
    using terminal::validation::BridgeUrl;
    using terminal::validation::DeviceId;
    using terminal::validation::PendingExpiry;
    using terminal::validation::SafeProvisioningForm;
    using terminal::validation::WifiCredential;

    Check(BridgeUrl("https://bridge.example.invalid/feed"), "HTTPS feed URL");
    Check(BridgeUrl("http://192.168.4.1:8080/feed"), "RFC1918 HTTP URL");
    Check(BridgeUrl("http://100.100.20.10/feed"), "tailnet HTTP URL");
    Check(BridgeUrl("http://terminal.local/feed"), "mDNS HTTP URL");
    Check(BridgeUrl("http://bridge/feed"), "single-label LAN HTTP URL");
    Check(BridgeUrl("https://[2001:db8::1]/feed"), "HTTPS IPv6 URL");

    Check(!BridgeUrl("http://example.com/feed"), "public HTTP must fail");
    Check(!BridgeUrl("ftp://bridge.local/feed"), "non-HTTP scheme must fail");
    Check(!BridgeUrl("HTTPS://bridge.example.invalid/feed"), "mixed-case scheme must fail");
    Check(!BridgeUrl("https://user:pass@bridge.example.invalid/feed"), "URL userinfo must fail");
    Check(!BridgeUrl("https://bridge.example.invalid/feed#fragment"), "fragment must fail");
    Check(!BridgeUrl("http://192.168.4.1:/feed"), "empty port must fail");
    Check(!BridgeUrl("http://010.0.0.1/feed"), "ambiguous leading-zero IPv4 must fail");
    Check(!BridgeUrl("http://12345/feed"), "numeric single-label host must fail");
    Check(!BridgeUrl("http://[2001:db8::1]/feed"), "public IPv6 HTTP must fail");
    Check(!BridgeUrl("https://bridge.example.invalid/a b"), "URL whitespace must fail");
    Check(!BridgeUrl("https://br\xC3\xAF" "dge.local/feed"), "non-ASCII URL must fail");

    const std::string valid_token(32, 'a');
    Check(BearerToken(valid_token), "valid bearer token");
    Check(!BearerToken("short"), "short bearer token must fail");
    Check(!BearerToken(std::string(20, 'a') + "\r\nInjected: yes"), "header injection must fail");

    Check(WifiCredential("LocalNetwork", "correct-horse"), "secured Wi-Fi");
    Check(WifiCredential("OpenNetwork", ""), "open Wi-Fi");
    Check(!WifiCredential("", "correct-horse"), "empty SSID must fail");
    Check(!WifiCredential("LocalNetwork", "short"), "short non-empty password must fail");

    Check(DeviceId("123e4567-e89b-42d3-a456-426614174000"), "UUIDv4 device ID");
    Check(!DeviceId("123e4567-e89b-12d3-a456-426614174000"), "non-v4 UUID must fail");
    int64_t expiry = 0;
    Check(PendingExpiry("1900000000", &expiry) && expiry == 1900000000,
          "pending expiry");
    Check(!PendingExpiry("-1"), "negative pending expiry must fail");

    const std::string safe_form =
        "csrf=abc&ssid=Home&password=correct-horse&"
        "bridge_url=http%3A%2F%2F100.100.20.10%3A8788%2Fv1%2Fdevice-feed&"
        "device_id=123e4567-e89b-42d3-a456-426614174000&"
        "pending_token=cbat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&"
        "pending_expires_at=1900000000";
    Check(SafeProvisioningForm(safe_form), "safe provisioning form");
    Check(SafeProvisioningForm(
              "setup_csrf=abc&ssid=Home&password=correct-horse&"
              "bridge_url=http%3A%2F%2F100.100.20.10%3A8788%2Fv1%2Fdevice-feed&"
              "device_id=123e4567-e89b-42d3-a456-426614174000&"
              "pending_token=cbat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&"
              "pending_expires_at=1900000000"),
          "localhost fallback provisioning form");
    Check(!SafeProvisioningForm(safe_form + "&privateKey=forbidden"),
          "API key field must never reach ESP save");
    Check(!SafeProvisioningForm(safe_form + "&ssid=duplicate"),
          "duplicate ESP fields must fail");
    Check(!SafeProvisioningForm(
              "ssid=Home&password=-----BEGIN%20PRIVATE%20KEY-----&"
              "bridge_url=http%3A%2F%2F100.100.20.10%3A8788%2Fv1%2Fdevice-feed&"
              "device_id=123e4567-e89b-42d3-a456-426614174000&"
              "pending_token=token&pending_expires_at=1900000000"),
          "private key material must never reach ESP save");

    std::cout << "config validation tests passed\n";
    return 0;
}
