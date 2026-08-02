#include "config_validation.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <set>

namespace terminal::validation {
namespace {

bool Fail(std::string* reason, const char* message) {
    if (reason) *reason = message;
    return false;
}

std::string Lower(std::string_view value) {
    std::string out(value);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

bool EndsWith(std::string_view value, std::string_view suffix) {
    return value.size() >= suffix.size() &&
           value.substr(value.size() - suffix.size()) == suffix;
}

bool ParsePort(std::string_view value) {
    if (value.empty() || value.size() > 5) return false;
    unsigned port = 0;
    for (char c : value) {
        if (c < '0' || c > '9') return false;
        port = port * 10 + static_cast<unsigned>(c - '0');
    }
    return port >= 1 && port <= 65535;
}

bool ParseIpv4(std::string_view host, std::array<unsigned, 4>* octets) {
    std::array<unsigned, 4> parsed{};
    size_t start = 0;
    for (size_t i = 0; i < parsed.size(); ++i) {
        size_t end = (i == parsed.size() - 1) ? host.size() : host.find('.', start);
        if (end == std::string_view::npos || end == start || end - start > 3) return false;
        if (end - start > 1 && host[start] == '0') return false;  // avoid octal ambiguity
        unsigned part = 0;
        for (size_t p = start; p < end; ++p) {
            if (host[p] < '0' || host[p] > '9') return false;
            part = part * 10 + static_cast<unsigned>(host[p] - '0');
        }
        if (part > 255) return false;
        parsed[i] = part;
        start = end + 1;
    }
    if (start != host.size() + 1) return false;
    if (octets) *octets = parsed;
    return true;
}

bool IsLocalIpv4(const std::array<unsigned, 4>& ip) {
    return ip[0] == 10 || ip[0] == 127 ||
           (ip[0] == 169 && ip[1] == 254) ||
           (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
           (ip[0] == 192 && ip[1] == 168) ||
           (ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127);
}

bool IsLocalIpv6(std::string_view host) {
    const std::string lower = Lower(host);
    if (lower == "::1") return true;
    if (lower.rfind("fc", 0) == 0 || lower.rfind("fd", 0) == 0) return true;
    if (lower.size() >= 3 && lower[0] == 'f' && lower[1] == 'e' &&
        lower[2] >= '8' && lower[2] <= 'b') return true;
    return false;
}

bool IsLocalHostname(std::string_view host) {
    const std::string lower = Lower(host);
    if (lower == "localhost") return true;
    if (lower.find('.') == std::string::npos) {
        const bool numeric = !lower.empty() && std::all_of(lower.begin(), lower.end(), [](char c) {
            return c >= '0' && c <= '9';
        });
        return !numeric;
    }
    return EndsWith(lower, ".local") || EndsWith(lower, ".lan") ||
           EndsWith(lower, ".home.arpa") || EndsWith(lower, ".internal");
}

bool ValidHostname(std::string_view host) {
    if (host.empty() || host.size() > 253 || host.front() == '.' || host.back() == '.') return false;
    size_t label_size = 0;
    bool label_started_with_hyphen = false;
    for (size_t i = 0; i <= host.size(); ++i) {
        const bool boundary = i == host.size() || host[i] == '.';
        if (boundary) {
            if (label_size == 0 || label_size > 63 || label_started_with_hyphen ||
                (i && host[i - 1] == '-')) return false;
            label_size = 0;
            label_started_with_hyphen = false;
            continue;
        }
        const unsigned char c = static_cast<unsigned char>(host[i]);
        if (!(std::isalnum(c) || c == '-')) return false;
        if (label_size == 0) label_started_with_hyphen = c == '-';
        ++label_size;
    }
    return true;
}

int HexValue(char character) {
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    if (character >= 'A' && character <= 'F') return character - 'A' + 10;
    return -1;
}

bool StrictUrlDecode(std::string_view input, std::string* output) {
    output->clear();
    output->reserve(input.size());
    for (size_t index = 0; index < input.size(); ++index) {
        if (input[index] == '+') {
            output->push_back(' ');
        } else if (input[index] == '%') {
            if (index + 2 >= input.size()) return false;
            const int high = HexValue(input[index + 1]);
            const int low = HexValue(input[index + 2]);
            if (high < 0 || low < 0) return false;
            output->push_back(static_cast<char>((high << 4) | low));
            index += 2;
        } else {
            output->push_back(input[index]);
        }
    }
    return output->find('\0') == std::string::npos;
}

}  // namespace

bool BridgeUrl(std::string_view value, std::string* reason) {
    if (value.size() < 10 || value.size() > kMaxBridgeUrlBytes)
        return Fail(reason, "Bridge URL length is invalid");
    for (unsigned char c : value) {
        if (c <= 0x20 || c >= 0x7f || c == '\\')
            return Fail(reason, "Bridge URL contains whitespace or an unsafe character");
    }
    if (value.find('#') != std::string_view::npos)
        return Fail(reason, "Bridge URL fragments are not allowed");

    const size_t scheme_end = value.find("://");
    if (scheme_end == std::string_view::npos)
        return Fail(reason, "Bridge URL must begin with http:// or https://");
    const std::string scheme_text(value.substr(0, scheme_end));
    const std::string scheme = Lower(scheme_text);
    if (scheme != "http" && scheme != "https")
        return Fail(reason, "Bridge URL must begin with http:// or https://");
    if (scheme_text != scheme)
        return Fail(reason, "Bridge URL scheme must use lowercase http or https");

    const size_t authority_start = scheme_end + 3;
    const size_t authority_end = value.find_first_of("/?", authority_start);
    std::string_view authority = value.substr(
        authority_start,
        authority_end == std::string_view::npos ? value.size() - authority_start
                                                : authority_end - authority_start);
    if (authority.empty() || authority.find('@') != std::string_view::npos)
        return Fail(reason, "Bridge URL must not contain credentials");

    std::string_view host;
    std::string_view port;
    bool ipv6 = false;
    if (authority.front() == '[') {
        const size_t close = authority.find(']');
        if (close == std::string_view::npos || close == 1)
            return Fail(reason, "Bridge URL has an invalid IPv6 host");
        host = authority.substr(1, close - 1);
        ipv6 = true;
        for (char c : host) {
            if (!std::isxdigit(static_cast<unsigned char>(c)) && c != ':' && c != '.')
                return Fail(reason, "Bridge URL has an invalid IPv6 host");
        }
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':') return Fail(reason, "Bridge URL authority is invalid");
            port = authority.substr(close + 2);
            if (port.empty()) return Fail(reason, "Bridge URL port is missing");
        }
    } else {
        const size_t colon = authority.rfind(':');
        if (colon != std::string_view::npos) {
            if (authority.find(':') != colon) return Fail(reason, "IPv6 hosts must use brackets");
            host = authority.substr(0, colon);
            port = authority.substr(colon + 1);
            if (port.empty()) return Fail(reason, "Bridge URL port is missing");
        } else {
            host = authority;
        }
    }
    if (!port.empty() && !ParsePort(port)) return Fail(reason, "Bridge URL port is invalid");
    if (host.empty()) return Fail(reason, "Bridge URL host is missing");

    bool local_host = false;
    if (ipv6) {
        local_host = IsLocalIpv6(host);
    } else {
        std::array<unsigned, 4> ip{};
        if (ParseIpv4(host, &ip)) {
            local_host = IsLocalIpv4(ip);
        } else {
            if (!ValidHostname(host)) return Fail(reason, "Bridge URL host is invalid");
            local_host = IsLocalHostname(host);
        }
    }
    if (scheme == "http" && !local_host)
        return Fail(reason, "Plain HTTP is allowed only for local, private, or tailnet hosts");

    if (reason) reason->clear();
    return true;
}

bool BearerToken(std::string_view value, std::string* reason) {
    if (value.size() < kMinBearerTokenBytes || value.size() > kMaxBearerTokenBytes)
        return Fail(reason, "Bridge token length is invalid");
    for (unsigned char c : value) {
        if (c <= 0x20 || c >= 0x7f)
            return Fail(reason, "Bridge token must contain visible ASCII without spaces");
    }
    if (reason) reason->clear();
    return true;
}

bool PendingBearerToken(std::string_view value, std::string* reason) {
    if (value.size() != 48 || value.substr(0, 5) != "cbat_")
        return Fail(reason, "Pending bridge token format is invalid");
    for (char character : value.substr(5)) {
        const bool base64url = (character >= 'a' && character <= 'z') ||
                               (character >= 'A' && character <= 'Z') ||
                               (character >= '0' && character <= '9') ||
                               character == '_' || character == '-';
        if (!base64url)
            return Fail(reason, "Pending bridge token format is invalid");
    }
    if (reason) reason->clear();
    return true;
}

bool WifiCredential(std::string_view ssid, std::string_view password, std::string* reason) {
    if (ssid.empty() || ssid.size() > 32)
        return Fail(reason, "Wi-Fi network name must be 1-32 bytes");
    if (!password.empty() && (password.size() < 8 || password.size() > 64))
        return Fail(reason, "Wi-Fi password must be blank for an open network or 8-64 bytes");
    for (unsigned char c : ssid) {
        if (c == 0) return Fail(reason, "Wi-Fi network name contains a null byte");
    }
    for (unsigned char c : password) {
        if (c == 0) return Fail(reason, "Wi-Fi password contains a null byte");
    }
    if (reason) reason->clear();
    return true;
}

bool DeviceId(std::string_view value) {
    if (value.size() != 36) return false;
    for (size_t i = 0; i < value.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-') return false;
        } else if (!((value[i] >= '0' && value[i] <= '9') ||
                     (value[i] >= 'a' && value[i] <= 'f'))) {
            return false;
        }
    }
    return value[14] == '4' && (value[19] == '8' || value[19] == '9' ||
                                value[19] == 'a' || value[19] == 'b');
}

bool PendingExpiry(std::string_view value, int64_t* parsed) {
    if (value.empty() || value.size() > 10) return false;
    int64_t result = 0;
    for (char character : value) {
        if (character < '0' || character > '9') return false;
        result = result * 10 + static_cast<int64_t>(character - '0');
    }
    if (result <= 0) return false;
    if (parsed) *parsed = result;
    return true;
}

bool SafeProvisioningForm(std::string_view body, std::string* reason) {
    if (body.empty() || body.size() > 4096)
        return Fail(reason, "Provisioning request size is invalid");
    static const std::set<std::string> allowed = {
        "csrf", "setup_csrf", "ssid", "password", "bridge_url", "device_id",
        "bridge_token", "pending_token", "pending_expires_at"};
    std::set<std::string> seen;
    std::string decoded_body;
    if (!StrictUrlDecode(body, &decoded_body))
        return Fail(reason, "Provisioning request encoding is invalid");
    const std::string lower_body = Lower(decoded_body);
    if (lower_body.find("private key-----") != std::string::npos)
        return Fail(reason, "Provisioning request contains a forbidden value");

    size_t start = 0;
    while (start <= body.size()) {
        const size_t end = body.find('&', start);
        const std::string_view field = body.substr(
            start, end == std::string_view::npos ? body.size() - start : end - start);
        const size_t equals = field.find('=');
        if (field.empty() || equals == std::string_view::npos)
            return Fail(reason, "Provisioning request fields are invalid");
        std::string key;
        if (!StrictUrlDecode(field.substr(0, equals), &key) || !allowed.count(key) ||
            !seen.insert(key).second)
            return Fail(reason, "Provisioning request fields are invalid");
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    const bool active = seen.count("bridge_token") == 1 &&
                        !seen.count("pending_token") &&
                        !seen.count("pending_expires_at");
    const bool pending = !seen.count("bridge_token") &&
                         seen.count("pending_token") == 1 &&
                         seen.count("pending_expires_at") == 1;
    if (!seen.count("ssid") || !seen.count("password") ||
        !seen.count("bridge_url") || !seen.count("device_id") ||
        (!active && !pending))
        return Fail(reason, "Provisioning request is incomplete");
    if (reason) reason->clear();
    return true;
}

bool SafePendingAbortForm(std::string_view body, std::string* reason) {
    if (body.empty() || body.size() > 2048)
        return Fail(reason, "Pending abort request size is invalid");
    static const std::set<std::string> allowed = {
        "csrf", "setup_csrf", "bridge_url", "device_id", "pending_token"};
    std::set<std::string> seen;
    size_t start = 0;
    while (start <= body.size()) {
        const size_t end = body.find('&', start);
        const std::string_view field = body.substr(
            start, end == std::string_view::npos ? body.size() - start : end - start);
        const size_t equals = field.find('=');
        if (field.empty() || equals == std::string_view::npos)
            return Fail(reason, "Pending abort request fields are invalid");
        std::string key;
        if (!StrictUrlDecode(field.substr(0, equals), &key) || !allowed.count(key) ||
            !seen.insert(key).second)
            return Fail(reason, "Pending abort request fields are invalid");
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    const bool one_csrf = seen.count("csrf") + seen.count("setup_csrf") == 1;
    if (!one_csrf || !seen.count("bridge_url") || !seen.count("device_id") ||
        !seen.count("pending_token"))
        return Fail(reason, "Pending abort request is incomplete");
    if (reason) reason->clear();
    return true;
}

}  // namespace terminal::validation
