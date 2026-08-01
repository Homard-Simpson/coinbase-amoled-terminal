#include "network_portal.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "config_validation.h"
#include "esp_app_format.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "nvs.h"
#include "onboarding_metadata.h"
#include "runtime_config.h"

namespace {
constexpr char kTag[] = "network-portal";
constexpr int kPortalFallbackSeconds = 45;
constexpr int kOtaWindowSeconds = 300;
constexpr size_t kMaxCredentials = 5;
constexpr size_t kMaxFormBytes = 4096;
constexpr size_t kMaxUploadBytes = 7 * 1024 * 1024;
constexpr char kProjectName[] = "coinbase_amoled_terminal";
#if CONFIG_TERMINAL_BOARD_V1
constexpr char kBoardVersionSuffix[] = "-v1";
#else
constexpr char kBoardVersionSuffix[] = "-v2";
#endif

struct Credential {
    std::string ssid;
    std::string password;
};

std::vector<Credential> credentials;
httpd_handle_t http_server = nullptr;
esp_netif_t* ap_netif = nullptr;
esp_timer_handle_t connection_timer = nullptr;
esp_timer_handle_t ota_timer = nullptr;
TaskHandle_t dns_task = nullptr;
int dns_socket = -1;
volatile bool dns_running = false;

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

bool EndsWith(std::string_view value, std::string_view suffix) {
    return value.size() >= suffix.size() &&
           value.substr(value.size() - suffix.size()) == suffix;
}

std::string RandomHex(size_t bytes) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out(bytes * 2, '0');
    for (size_t i = 0; i < bytes; ++i) {
        const uint8_t value = static_cast<uint8_t>(esp_random());
        out[i * 2] = hex[value >> 4];
        out[i * 2 + 1] = hex[value & 0x0f];
    }
    return out;
}

std::string HtmlEscape(std::string_view value) {
    std::string out;
    out.reserve(value.size() + 16);
    for (char c : value) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '\"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out.push_back(c); break;
        }
    }
    return out;
}

std::string JsonString(std::string_view value) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out = "\"";
    out.reserve(value.size() + 12);
    for (unsigned char character : value) {
        if (character == '\\' || character == '\"') {
            out.push_back('\\');
            out.push_back(static_cast<char>(character));
        } else if (character < 0x20 || character == '<' || character == '>' ||
                   character == '&') {
            out += "\\u00";
            out.push_back(hex[character >> 4]);
            out.push_back(hex[character & 0x0f]);
        } else {
            out.push_back(static_cast<char>(character));
        }
    }
    out.push_back('\"');
    return out;
}

std::string UrlDecode(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '+') {
            out.push_back(' ');
        } else if (value[i] == '%' && i + 2 < value.size()) {
            char hex[3] = {value[i + 1], value[i + 2], 0};
            char* end = nullptr;
            const long decoded = strtol(hex, &end, 16);
            if (end && *end == 0) {
                out.push_back(static_cast<char>(decoded));
                i += 2;
            } else {
                out.push_back(value[i]);
            }
        } else {
            out.push_back(value[i]);
        }
    }
    return out;
}

std::string FormValue(const std::string& body, const char* name) {
    const std::string prefix = std::string(name) + "=";
    size_t start = 0;
    while ((start = body.find(prefix, start)) != std::string::npos) {
        if (start == 0 || body[start - 1] == '&') {
            start += prefix.size();
            const size_t end = body.find('&', start);
            return UrlDecode(body.substr(start, end == std::string::npos ? end : end - start));
        }
        start += prefix.size();
    }
    return {};
}

bool IsApClient(httpd_req_t* req) {
    sockaddr_storage peer{};
    socklen_t len = sizeof(peer);
    const int fd = httpd_req_to_sockfd(req);
    if (getpeername(fd, reinterpret_cast<sockaddr*>(&peer), &len) != 0) return false;
    const uint8_t* bytes = nullptr;
    if (peer.ss_family == AF_INET) {
        bytes = reinterpret_cast<const uint8_t*>(&reinterpret_cast<sockaddr_in*>(&peer)->sin_addr.s_addr);
    } else if (peer.ss_family == AF_INET6) {
        const auto* v6 = reinterpret_cast<const sockaddr_in6*>(&peer);
        const uint8_t* raw = v6->sin6_addr.s6_addr;
        if (raw[10] != 0xff || raw[11] != 0xff) return false;
        bytes = raw + 12;
    } else {
        return false;
    }
    return bytes[0] == 192 && bytes[1] == 168 && bytes[2] == 4;
}

std::string RequestHeader(httpd_req_t* req, const char* name, size_t maximum = 320) {
    const size_t length = httpd_req_get_hdr_value_len(req, name);
    if (length == 0 || length >= maximum) return {};
    std::string value(length + 1, '\0');
    if (httpd_req_get_hdr_value_str(req, name, value.data(), value.size()) != ESP_OK)
        return {};
    value.resize(length);
    return value;
}

bool CanonicalPortalHost(httpd_req_t* req) {
    const std::string host = RequestHeader(req, "Host", 64);
    return host == "192.168.4.1" || host == "192.168.4.1:80";
}

void SetSecurityHeaders(httpd_req_t* req, std::string_view connect_origin = {}) {
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_set_hdr(req, "Pragma", "no-cache");
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(req, "Referrer-Policy", "no-referrer");
    httpd_resp_set_hdr(req, "X-Frame-Options", "DENY");
    httpd_resp_set_hdr(req, "Permissions-Policy",
                       "camera=(), microphone=(), geolocation=()");
    static constexpr char kPortalPolicy[] =
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
    static constexpr char kOnboardingPolicy[] =
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "connect-src 'self' http://127.0.0.1:*; form-action 'self'; base-uri 'none'; "
        "frame-ancestors 'none'";
    httpd_resp_set_hdr(req, "Content-Security-Policy",
                       connect_origin.empty() ? kPortalPolicy : kOnboardingPolicy);
}

bool IsFormContentType(httpd_req_t* req) {
    return RequestHeader(req, "Content-Type", 96) ==
           "application/x-www-form-urlencoded";
}

bool SetSaveCorsHeaders(httpd_req_t* req, const std::string& origin,
                        const OnboardingMetadataSnapshot& setup,
                        bool preflight = false) {
    if (origin.empty() || origin == "http://192.168.4.1") return true;
    if (!setup.IsAvailable() || origin != setup.endpoint_origin) return false;
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", origin.c_str());
    httpd_resp_set_hdr(req, "Vary", "Origin");
    if (preflight) {
        httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "POST");
        httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Content-Type");
        httpd_resp_set_hdr(req, "Access-Control-Max-Age", "0");
        if (RequestHeader(req, "Access-Control-Request-Private-Network", 16) == "true")
            httpd_resp_set_hdr(req, "Access-Control-Allow-Private-Network", "true");
    }
    return true;
}

bool ReadRequestBody(httpd_req_t* req, std::string* body) {
    if (req->content_len <= 0 || static_cast<size_t>(req->content_len) > kMaxFormBytes) return false;
    body->assign(req->content_len, '\0');
    int received = 0;
    while (received < req->content_len) {
        const int count = httpd_req_recv(req, body->data() + received, req->content_len - received);
        if (count == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (count <= 0) return false;
        received += count;
    }
    return true;
}

std::string RenderUsbOnboardingHtml(const OnboardingMetadataSnapshot& setup) {
    const std::string portal_csrf = NetworkPortal::GetInstance().GetCsrfToken();
    std::string html = R"HTML(<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AMOLED Terminal Setup</title><style>body{font:16px system-ui;background:#07101f;color:#f5f7fa;max-width:560px;margin:28px auto;padding:0 18px}section{background:#121826;padding:22px;border-radius:14px}label{display:block;margin-top:13px}input,textarea,button{box-sizing:border-box;width:100%;padding:12px;margin:6px 0;border-radius:8px;border:1px solid #526079}textarea{min-height:120px}button{background:#377eff;color:white;font-weight:700}small,.muted{color:#b8c1d1}#status{white-space:pre-wrap}.fallback{display:none}a{color:#8ab4ff}</style></head><body><h1>Connect your display</h1><p class="muted">Add home Wi-Fi and a view-only Coinbase key. The key goes straight to the bridge on this computer. This display never receives it.</p><section><form id="setup" autocomplete="off"><label>Home Wi-Fi name</label><input id="ssid" maxlength="32" autocomplete="off" required><label>Home Wi-Fi password</label><input id="wifiPassword" type="password" maxlength="64" autocomplete="new-password"><label>Coinbase CDP ECDSA API-key JSON</label><textarea id="keyText" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="Paste the downloaded JSON"></textarea><input id="keyFile" type="file" accept="application/json,.json" autocomplete="off"><small>Unsafe keys with trade or transfer permission are rejected.</small><button id="finish" type="submit">Finish</button><p id="status" aria-live="polite"></p><p class="fallback" id="fallback">The captive window could not reach this computer. <a href=")HTML";
    html += HtmlEscape(setup.local_page_url);
    html += R"HTML(" target="_blank" rel="noreferrer noopener">Continue on this computer</a>. If the key check needs internet, reconnect this computer to its usual network there, then return to this display Wi-Fi.</p></form></section><script>'use strict';const endpoint=)HTML";
    html += JsonString(setup.endpoint_url);
    html += ",provisionEndpoint=" + JsonString(setup.endpoint_origin + "/v1/onboarding/provisioning");
    html += ",finishEndpoint=" + JsonString(setup.endpoint_origin + "/v1/onboarding/finish");
    html += ",sessionId=" + JsonString(setup.session_id);
    html += ",setupToken=" + JsonString(setup.setup_token);
    html += ",setupCsrf=" + JsonString(setup.csrf_token);
    html += ",portalCsrf=" + JsonString(portal_csrf) + ";";
    html += R"HTML(const baseHeaders=()=>({'Authorization':'Setup '+setupToken,'X-Setup-Session':sessionId,'X-CSRF-Token':setupCsrf});async function keyDocument(){const f=document.getElementById('keyFile').files[0];return f?await f.text():document.getElementById('keyText').value}async function completedProvisioning(){const r=await fetch(provisionEndpoint,{method:'POST',mode:'cors',cache:'no-store',credentials:'omit',redirect:'error',referrerPolicy:'no-referrer',headers:baseHeaders()});if(!r.ok)throw new Error('not-ready');return r.json()}async function checkKey(key){const headers=baseHeaders();headers['Content-Type']='application/json';const r=await fetch(endpoint,{method:'POST',mode:'cors',cache:'no-store',credentials:'omit',redirect:'error',referrerPolicy:'no-referrer',headers,body:key});if(!r.ok)throw new Error('key');return r.json()}async function saveOnlySafeValues(p){const body=new URLSearchParams();body.set('csrf',portalCsrf);body.set('ssid',document.getElementById('ssid').value);body.set('password',document.getElementById('wifiPassword').value);body.set('bridge_url',p.bridge_url);body.set('device_id',p.device_id);body.set('bridge_token',p.feed_token);const r=await fetch('/save',{method:'POST',cache:'no-store',credentials:'omit',redirect:'error',referrerPolicy:'no-referrer',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body.toString()});if(!r.ok)throw new Error('save')}async function acknowledge(){const r=await fetch(finishEndpoint,{method:'POST',mode:'cors',cache:'no-store',credentials:'omit',redirect:'error',referrerPolicy:'no-referrer',headers:baseHeaders()});if(!r.ok)throw new Error('finish')}document.getElementById('setup').addEventListener('submit',async e=>{e.preventDefault();const out=document.getElementById('status'),button=document.getElementById('finish');button.disabled=true;out.textContent='Checking the read-only key…';try{let key=await keyDocument();document.getElementById('keyText').value='';document.getElementById('keyFile').value='';let p;if(key.trim()){p=await checkKey(key);key=''}else{out.textContent='Getting the completed key check from this computer…';p=await completedProvisioning()}await saveOnlySafeValues(p);await acknowledge();document.getElementById('wifiPassword').value='';out.textContent='Setup complete. The display is restarting.'}catch(_error){out.textContent='Setup could not be completed here. Continue on this computer, then return and press Finish with the key field empty.';document.getElementById('fallback').style.display='block';button.disabled=false}});</script></body></html>)HTML";
    return html;
}

std::string RenderPortalHtml() {
    auto& portal = NetworkPortal::GetInstance();
    const RuntimeConfigSnapshot runtime = RuntimeConfig::GetInstance().Snapshot();
    const bool configured = runtime.IsProvisioned();
    const OnboardingMetadataSnapshot setup = OnboardingMetadata::GetInstance().Snapshot();
    if (setup.IsAvailable()) return RenderUsbOnboardingHtml(setup);
    const bool has_wifi = portal.HasSavedNetwork();
    const std::string current_url = HtmlEscape(runtime.bridge_url);
    const std::string device_id = HtmlEscape(runtime.device_id);
    const std::string csrf = HtmlEscape(portal.GetCsrfToken());
    const std::string token_hint = configured
        ? "Leave blank to keep the stored token"
        : "Required: bridge-issued per-device token";
    const std::string wifi_hint = has_wifi
        ? "Leave network name blank to keep saved Wi-Fi"
        : "Required on first boot";

    std::string html = R"HTML(<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>AMOLED Terminal Setup</title><style>body{font:16px system-ui;background:#07101f;color:#f5f7fa;max-width:560px;margin:28px auto;padding:0 18px}section{background:#121826;padding:20px;border-radius:14px;margin:16px 0}input,button{box-sizing:border-box;width:100%;padding:12px;margin:7px 0;border-radius:8px;border:1px solid #526079}button{background:#377eff;color:white;font-weight:700}.danger{background:#a61b29}small,.muted{color:#b8c1d1}code{overflow-wrap:anywhere}.status{white-space:pre-wrap}</style></head><body><h1>AMOLED Terminal</h1><p class="muted">Advanced manual bridge setup. Never enter a Coinbase API key on this display.</p><section><h2>Device identity</h2><p>Register this generated ID with your local bridge:</p><code>)HTML";
    html += device_id;
    html += "</code><p class=\"muted\">This is not a hardware MAC address and is not an exchange credential.</p></section>";
    html += R"HTML(<section><h2>Connection</h2><form method="post" action="/save" autocomplete="off"><input type="hidden" name="csrf" value=")HTML";
    html += csrf;
    html += R"HTML("><label>Wi-Fi network name</label><input name="ssid" maxlength="32" autocomplete="off"><small>)HTML";
    html += wifi_hint;
    html += R"HTML(</small><label>Wi-Fi password</label><input name="password" type="password" maxlength="64" autocomplete="new-password"><label>Bridge feed URL</label><input name="bridge_url" type="url" maxlength="255" required value=")HTML";
    html += current_url;
    html += R"HTML(" placeholder="https://bridge.example.invalid/feed"><input type="hidden" name="device_id" value=")HTML";
    html += device_id;
    html += R"HTML("><small>HTTPS is accepted anywhere. Plain HTTP is limited to private, local, or tailnet hosts.</small><label>Bridge bearer token</label><input name="bridge_token" type="password" maxlength="512" autocomplete="new-password"><small>)HTML";
    html += token_hint;
    html += R"HTML(. Never enter Coinbase API keys here.</small><button>Save and restart</button></form></section><section><h2>Firmware update</h2><p>OTA is disabled unless physically armed. Hold BOOT for 10 seconds, then enter the six-digit code shown on the display.</p><input id="code" inputmode="numeric" maxlength="6" placeholder="One-time code"><input id="file" type="file" accept=".bin,application/octet-stream"><button type="button" onclick="uploadFirmware()">Install firmware</button><div class="status" id="out"></div><small>Use the image for this exact board revision. The inactive slot is selected only after full ESP-IDF image validation.</small></section><section><h2>Factory reset</h2><p>Erases Wi-Fi, bridge URL, bridge token, generated device ID, and setup password. Firmware remains installed.</p><form method="post" action="/factory-reset"><input type="hidden" name="csrf" value=")HTML";
    html += csrf;
    html += R"HTML("><input name="confirm" autocomplete="off" placeholder="Type RESET"><button class="danger">Erase configuration</button></form></section><script>async function uploadFirmware(){const o=document.getElementById('out'),f=document.getElementById('file').files[0],c=document.getElementById('code').value;if(!f||!/^[0-9]{6}$/.test(c)){o.textContent='Choose a .bin and enter the six-digit screen code.';return}o.textContent='Uploading; keep the device powered.';try{const r=await fetch('/ota',{method:'POST',headers:{'Content-Type':'application/octet-stream','X-OTA-Code':c},body:f});o.textContent=await r.text()}catch(e){o.textContent='Connection closed. If validation completed, the device is restarting.'}}</script></body></html>)HTML";
    return html;
}

void RestartTask(void*) {
    vTaskDelay(pdMS_TO_TICKS(1500));
    esp_restart();
}

void FactoryResetTask(void*) {
    vTaskDelay(pdMS_TO_TICKS(1500));
    OnboardingMetadata::GetInstance().Clear();
    for (const char* name : {"wifi", "terminal"}) {
        nvs_handle_t nvs = 0;
        if (nvs_open(name, NVS_READWRITE, &nvs) == ESP_OK) {
            nvs_erase_all(nvs);
            nvs_commit(nvs);
            nvs_close(nvs);
        }
    }
    esp_restart();
}

esp_err_t RedirectHandler(httpd_req_t* req);

esp_err_t RootHandler(httpd_req_t* req) {
    if (!IsApClient(req)) return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "AP clients only");
    if (!CanonicalPortalHost(req)) return RedirectHandler(req);
    const std::string html = RenderPortalHtml();
    const OnboardingMetadataSnapshot setup = OnboardingMetadata::GetInstance().Snapshot();
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    SetSecurityHeaders(req, setup.IsAvailable() ? setup.endpoint_origin : "");
    return httpd_resp_send(req, html.c_str(), html.size());
}

esp_err_t RedirectHandler(httpd_req_t* req) {
    if (!IsApClient(req)) return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "AP clients only");
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "http://192.168.4.1/");
    SetSecurityHeaders(req);
    return httpd_resp_send(req, nullptr, 0);
}

esp_err_t SaveHandler(httpd_req_t* req) {
    auto& portal = NetworkPortal::GetInstance();
    const std::string origin = RequestHeader(req, "Origin", 320);
    const OnboardingMetadataSnapshot setup = OnboardingMetadata::GetInstance().Snapshot();
    SetSecurityHeaders(req);
    if (!IsApClient(req)) return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "AP clients only");
    if (!CanonicalPortalHost(req) || !SetSaveCorsHeaders(req, origin, setup) ||
        !IsFormContentType(req))
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Setup request refused");
    std::string body;
    if (!ReadRequestBody(req, &body)) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid form");
    std::string reason;
    if (!terminal::validation::SafeProvisioningForm(body, &reason))
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid setup details");

    const bool localhost_fallback = setup.IsAvailable() && origin == setup.endpoint_origin;
    const bool csrf_valid = localhost_fallback
        ? FormValue(body, "setup_csrf") == setup.csrf_token
        : FormValue(body, "csrf") == portal.GetCsrfToken();
    if (!csrf_valid)
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Expired setup form; reload and try again");

    const std::string ssid = FormValue(body, "ssid");
    const std::string password = FormValue(body, "password");
    const std::string bridge_url = FormValue(body, "bridge_url");
    const std::string device_id = FormValue(body, "device_id");
    const std::string bridge_token = FormValue(body, "bridge_token");
    if (!ssid.empty() && !terminal::validation::WifiCredential(ssid, password, &reason))
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, reason.c_str());
    if (ssid.empty() && !portal.HasSavedNetwork())
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Wi-Fi network name is required on first setup");

    esp_err_t err = RuntimeConfig::GetInstance().SaveProvisioning(
        bridge_url, device_id, bridge_token, &reason);
    if (err == ESP_ERR_INVALID_ARG)
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, reason.c_str());
    if (err != ESP_OK)
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Unable to store bridge configuration");
    if (!ssid.empty() && portal.SaveCredential(ssid, password) != ESP_OK)
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Unable to store Wi-Fi configuration");
    if (setup.IsAvailable() && OnboardingMetadata::GetInstance().Clear() != ESP_OK)
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Unable to close one-time setup");

    httpd_resp_set_type(req, "text/plain");
    SetSaveCorsHeaders(req, origin, setup);
    SetSecurityHeaders(req);
    httpd_resp_sendstr(req, "Configuration saved. The display is restarting.");
    xTaskCreate(RestartTask, "setup_restart", 2048, nullptr, 5, nullptr);
    return ESP_OK;
}

esp_err_t SaveOptionsHandler(httpd_req_t* req) {
    const std::string origin = RequestHeader(req, "Origin", 320);
    const OnboardingMetadataSnapshot setup = OnboardingMetadata::GetInstance().Snapshot();
    SetSecurityHeaders(req);
    if (!IsApClient(req) || !CanonicalPortalHost(req) ||
        !SetSaveCorsHeaders(req, origin, setup, true) ||
        RequestHeader(req, "Access-Control-Request-Method", 16) != "POST" ||
        RequestHeader(req, "Access-Control-Request-Headers", 64) != "content-type") {
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Setup request refused");
    }
    SetSecurityHeaders(req);
    httpd_resp_set_status(req, "204 No Content");
    return httpd_resp_send(req, nullptr, 0);
}

esp_err_t FactoryResetHandler(httpd_req_t* req) {
    auto& portal = NetworkPortal::GetInstance();
    SetSecurityHeaders(req);
    if (!IsApClient(req)) return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "AP clients only");
    std::string body;
    if (!ReadRequestBody(req, &body)) return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid form");
    if (FormValue(body, "csrf") != portal.GetCsrfToken())
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Expired setup form; reload and try again");
    if (FormValue(body, "confirm") != "RESET")
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Type RESET exactly to erase configuration");
    httpd_resp_set_type(req, "text/plain");
    SetSecurityHeaders(req);
    httpd_resp_sendstr(req, "Configuration erased. The display will restart in first-boot setup mode.");
    xTaskCreate(FactoryResetTask, "factory_reset", 3072, nullptr, 5, nullptr);
    return ESP_OK;
}

esp_err_t OtaHandler(httpd_req_t* req) {
    auto& portal = NetworkPortal::GetInstance();
    SetSecurityHeaders(req);
    if (!IsApClient(req)) return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "AP clients only");
    if (!portal.IsOtaArmed()) return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "OTA is not physically armed");
    char code[16]{};
    if (httpd_req_get_hdr_value_str(req, "X-OTA-Code", code, sizeof(code)) != ESP_OK ||
        portal.GetOtaCode() != code)
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "Wrong one-time code");
    if (req->content_len < 1024 || static_cast<size_t>(req->content_len) > kMaxUploadBytes)
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid firmware size");

    const esp_partition_t* update = esp_ota_get_next_update_partition(nullptr);
    if (!update || static_cast<size_t>(req->content_len) > update->size)
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "No suitable OTA slot");

    constexpr size_t app_desc_offset = sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t);
    constexpr size_t required_header = app_desc_offset + sizeof(esp_app_desc_t);
    std::vector<uint8_t> buffer(4096);
    int first_len = 0;
    while (first_len < static_cast<int>(required_header) && first_len < req->content_len) {
        const int count = httpd_req_recv(req, reinterpret_cast<char*>(buffer.data()) + first_len,
                                         std::min<int>(buffer.size() - first_len,
                                                       req->content_len - first_len));
        if (count == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (count <= 0) return ESP_FAIL;
        first_len += count;
    }
    if (first_len < static_cast<int>(required_header))
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Truncated firmware header");

    const auto* desc = reinterpret_cast<const esp_app_desc_t*>(buffer.data() + app_desc_offset);
    const std::string_view project(desc->project_name, strnlen(desc->project_name, sizeof(desc->project_name)));
    const std::string_view version(desc->version, strnlen(desc->version, sizeof(desc->version)));
    if (desc->magic_word != ESP_APP_DESC_MAGIC_WORD || project != kProjectName)
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Not an AMOLED terminal firmware image");
    if (!EndsWith(version, kBoardVersionSuffix))
        return httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Firmware image is for the other board revision");
    const esp_app_desc_t new_app_desc = *desc;

    esp_ota_handle_t handle = 0;
    esp_err_t err = esp_ota_begin(update, req->content_len, &handle);
    bool began = err == ESP_OK;
    if (err == ESP_OK) err = esp_ota_write(handle, buffer.data(), first_len);
    int total = first_len;
    while (err == ESP_OK && total < req->content_len) {
        const int count = httpd_req_recv(req, reinterpret_cast<char*>(buffer.data()),
                                         std::min<int>(buffer.size(), req->content_len - total));
        if (count == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (count <= 0) { err = ESP_FAIL; break; }
        err = esp_ota_write(handle, buffer.data(), count);
        total += count;
    }
    if (err == ESP_OK) {
        err = esp_ota_end(handle);
        began = false;
    }
    if (err != ESP_OK && began) esp_ota_abort(handle);
    if (err == ESP_OK) err = esp_ota_set_boot_partition(update);
    if (err != ESP_OK) {
        ESP_LOGE(kTag, "OTA failed after %d bytes: %s", total, esp_err_to_name(err));
        return httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                                   "Firmware validation or write failed; current firmware remains selected");
    }

    ESP_LOGI(kTag, "OTA accepted version=%s bytes=%d slot=%s",
             new_app_desc.version, total, update->label);
    httpd_resp_set_type(req, "text/plain");
    SetSecurityHeaders(req);
    httpd_resp_sendstr(req, "Firmware validated. Restarting into the inactive slot.");
    xTaskCreate(RestartTask, "ota_restart", 2048, nullptr, 5, nullptr);
    return ESP_OK;
}

void DnsTask(void*) {
    dns_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("192.168.4.1");
    server.sin_port = htons(53);
    if (dns_socket < 0 || bind(dns_socket, reinterpret_cast<sockaddr*>(&server), sizeof(server)) < 0) {
        ESP_LOGE(kTag, "captive DNS bind failed errno=%d", errno);
        if (dns_socket >= 0) close(dns_socket);
        dns_socket = -1;
        dns_running = false;
        dns_task = nullptr;
        vTaskDelete(nullptr);
        return;
    }

    std::array<uint8_t, 512> packet{};
    while (dns_running) {
        sockaddr_in client{};
        socklen_t client_len = sizeof(client);
        const int length = recvfrom(dns_socket, packet.data(), packet.size() - 16, 0,
                                    reinterpret_cast<sockaddr*>(&client), &client_len);
        if (length < 12 || !dns_running) continue;
        packet[2] |= 0x80;
        packet[3] |= 0x80;
        packet[6] = 0;
        packet[7] = 1;
        const uint8_t answer[] = {
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x1c, 0x00, 0x04, 192, 168, 4, 1
        };
        memcpy(packet.data() + length, answer, sizeof(answer));
        sendto(dns_socket, packet.data(), length + sizeof(answer), 0,
               reinterpret_cast<sockaddr*>(&client), client_len);
    }
    dns_task = nullptr;
    vTaskDelete(nullptr);
}
}  // namespace

NetworkPortal& NetworkPortal::GetInstance() {
    static NetworkPortal instance;
    return instance;
}

void NetworkPortal::NotifyState() {
    if (state_callback_) state_callback_();
}

bool NetworkPortal::HasSavedNetwork() const {
    ScopedLock guard(state_lock_);
    return !credentials.empty();
}

std::string NetworkPortal::GetApSsid() const {
    ScopedLock guard(state_lock_);
    return ap_ssid_;
}

std::string NetworkPortal::GetApPassword() const {
    ScopedLock guard(state_lock_);
    return ap_password_;
}

std::string NetworkPortal::GetOtaCode() const {
    ScopedLock guard(state_lock_);
    return ota_code_;
}

std::string NetworkPortal::GetCsrfToken() const {
    ScopedLock guard(state_lock_);
    return csrf_token_;
}

void NetworkPortal::LoadCredentials() {
    ScopedLock guard(state_lock_);
    credentials.clear();
    nvs_handle_t nvs = 0;
    if (nvs_open("wifi", NVS_READONLY, &nvs) != ESP_OK) return;
    for (size_t i = 0; i < kMaxCredentials; ++i) {
        const std::string suffix = i ? std::to_string(i) : "";
        char ssid[33]{}, password[65]{};
        size_t ssid_len = sizeof(ssid), password_len = sizeof(password);
        if (nvs_get_str(nvs, ("ssid" + suffix).c_str(), ssid, &ssid_len) == ESP_OK && ssid[0] &&
            nvs_get_str(nvs, ("password" + suffix).c_str(), password, &password_len) == ESP_OK) {
            credentials.push_back({ssid, password});
        }
    }
    nvs_close(nvs);
}

esp_err_t NetworkPortal::SaveCredential(const std::string& ssid, const std::string& password) {
    std::string reason;
    if (!terminal::validation::WifiCredential(ssid, password, &reason)) return ESP_ERR_INVALID_ARG;
    ScopedLock guard(state_lock_);
    credentials.erase(std::remove_if(credentials.begin(), credentials.end(),
                                     [&](const Credential& item) { return item.ssid == ssid; }),
                      credentials.end());
    credentials.insert(credentials.begin(), {ssid, password});
    if (credentials.size() > kMaxCredentials) credentials.resize(kMaxCredentials);

    nvs_handle_t nvs = 0;
    esp_err_t err = nvs_open("wifi", NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;
    for (size_t i = 0; i < kMaxCredentials && err == ESP_OK; ++i) {
        const std::string suffix = i ? std::to_string(i) : "";
        const std::string ssid_key = "ssid" + suffix;
        const std::string password_key = "password" + suffix;
        if (i < credentials.size()) {
            err = nvs_set_str(nvs, ssid_key.c_str(), credentials[i].ssid.c_str());
            if (err == ESP_OK) err = nvs_set_str(nvs, password_key.c_str(), credentials[i].password.c_str());
        } else {
            const esp_err_t ssid_err = nvs_erase_key(nvs, ssid_key.c_str());
            const esp_err_t password_err = nvs_erase_key(nvs, password_key.c_str());
            if (ssid_err != ESP_OK && ssid_err != ESP_ERR_NVS_NOT_FOUND) err = ssid_err;
            if (password_err != ESP_OK && password_err != ESP_ERR_NVS_NOT_FOUND) err = password_err;
        }
    }
    if (err == ESP_OK) err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}

void NetworkPortal::ApplyCredential(size_t index) {
    ScopedLock guard(state_lock_);
    if (credentials.empty()) return;
    credential_index_ = index % credentials.size();
    wifi_config_t config{};
    strlcpy(reinterpret_cast<char*>(config.sta.ssid), credentials[credential_index_].ssid.c_str(),
            sizeof(config.sta.ssid));
    strlcpy(reinterpret_cast<char*>(config.sta.password), credentials[credential_index_].password.c_str(),
            sizeof(config.sta.password));
    config.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    config.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
    config.sta.threshold.authmode = WIFI_AUTH_OPEN;
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &config));
}

void NetworkPortal::Initialize(std::function<void(bool)> connection_callback,
                               std::function<void()> state_callback) {
    connection_callback_ = std::move(connection_callback);
    state_callback_ = std::move(state_callback);
    if (!state_lock_) {
        state_lock_ = xSemaphoreCreateMutex();
        if (!state_lock_) abort();
    }
    LoadCredentials();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    init.nvs_enable = false;
    ESP_ERROR_CHECK(esp_wifi_init(&init));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, EventHandler, this));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, EventHandler, this));

    const bool setup_required = !RuntimeConfig::GetInstance().IsProvisioned();
    const bool usb_onboarding = OnboardingMetadata::GetInstance().IsAvailable();
    const bool start_portal = !HasSavedNetwork() || setup_required || usb_onboarding;
    ESP_ERROR_CHECK(esp_wifi_set_mode(start_portal ? WIFI_MODE_APSTA : WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    if (start_portal) {
        StartPortal();
    } else {
        esp_timer_create_args_t args{};
        args.callback = ConnectionTimeout;
        args.arg = this;
        args.name = "wifi_fallback";
        ESP_ERROR_CHECK(esp_timer_create(&args, &connection_timer));
        ESP_ERROR_CHECK(esp_timer_start_once(connection_timer,
                                              kPortalFallbackSeconds * 1000000ULL));
    }
    ESP_LOGI(kTag, "network initialized has_saved_network=%d setup_required=%d",
             HasSavedNetwork(), setup_required);
}

void NetworkPortal::EventHandler(void* arg, const char* event_base, int32_t event_id,
                                 void*) {
    auto* self = static_cast<NetworkPortal*>(arg);
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START && self->HasSavedNetwork()) {
        self->ApplyCredential(0);
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        self->connected_ = true;
        if (connection_timer) esp_timer_stop(connection_timer);
        if (!self->ota_armed_ && RuntimeConfig::GetInstance().IsProvisioned() &&
            !OnboardingMetadata::GetInstance().IsAvailable()) self->StopPortal();
        if (self->connection_callback_) self->connection_callback_(true);
        self->NotifyState();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED &&
               self->HasSavedNetwork()) {
        const bool was_connected = self->connected_.exchange(false);
        self->ApplyCredential(self->credential_index_ + 1);
        esp_wifi_connect();
        if (was_connected && connection_timer && !self->portal_active_) {
            esp_timer_stop(connection_timer);
            esp_timer_start_once(connection_timer, kPortalFallbackSeconds * 1000000ULL);
        }
        if (was_connected && self->connection_callback_) self->connection_callback_(false);
        self->NotifyState();
    }
}

void NetworkPortal::ConnectionTimeout(void* arg) {
    auto* self = static_cast<NetworkPortal*>(arg);
    if (!self->connected_) self->StartPortal();
}

void NetworkPortal::OtaTimeout(void* arg) {
    auto* self = static_cast<NetworkPortal*>(arg);
    self->ota_armed_ = false;
    {
        ScopedLock guard(self->state_lock_);
        self->ota_code_.clear();
    }
    self->NotifyState();
    if (self->connected_ && RuntimeConfig::GetInstance().IsProvisioned())
        xTaskCreate(ClosePortalTask, "portal_close", 4096, self, 4, nullptr);
}

void NetworkPortal::ClosePortalTask(void* arg) {
    static_cast<NetworkPortal*>(arg)->StopPortal();
    vTaskDelete(nullptr);
}

void NetworkPortal::StartPortal() {
    if (portal_active_.exchange(true)) return;
    const RuntimeConfigSnapshot runtime = RuntimeConfig::GetInstance().Snapshot();
    const std::string suffix = runtime.device_id.size() >= 4
        ? runtime.device_id.substr(runtime.device_id.size() - 4) : "setup";
    {
        ScopedLock guard(state_lock_);
        ap_ssid_ = "AMOLED-Terminal-" + suffix;
        ap_password_ = runtime.setup_ap_password;
        csrf_token_ = RandomHex(16);
    }

    if (!ap_netif) ap_netif = esp_netif_create_default_wifi_ap();
    esp_netif_ip_info_t ip{};
    IP4_ADDR(&ip.ip, 192, 168, 4, 1);
    IP4_ADDR(&ip.gw, 192, 168, 4, 1);
    IP4_ADDR(&ip.netmask, 255, 255, 255, 0);
    esp_netif_dhcps_stop(ap_netif);
    ESP_ERROR_CHECK(esp_netif_set_ip_info(ap_netif, &ip));
    ESP_ERROR_CHECK(esp_netif_dhcps_start(ap_netif));

    wifi_config_t config{};
    const std::string ssid = GetApSsid();
    const std::string password = GetApPassword();
    strlcpy(reinterpret_cast<char*>(config.ap.ssid), ssid.c_str(), sizeof(config.ap.ssid));
    strlcpy(reinterpret_cast<char*>(config.ap.password), password.c_str(), sizeof(config.ap.password));
    config.ap.ssid_len = ssid.size();
    config.ap.max_connection = 2;
    config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    config.ap.pmf_cfg.capable = true;
    config.ap.pmf_cfg.required = true;
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &config));

    httpd_config_t server_config = HTTPD_DEFAULT_CONFIG();
    server_config.max_uri_handlers = 12;
    server_config.stack_size = 8192;
    server_config.uri_match_fn = httpd_uri_match_wildcard;
    server_config.recv_wait_timeout = 20;
    server_config.send_wait_timeout = 20;
    ESP_ERROR_CHECK(httpd_start(&http_server, &server_config));
    httpd_uri_t root{};
    root.uri = "/"; root.method = HTTP_GET; root.handler = RootHandler;
    ESP_ERROR_CHECK(httpd_register_uri_handler(http_server, &root));
    httpd_uri_t save{};
    save.uri = "/save"; save.method = HTTP_POST; save.handler = SaveHandler;
    ESP_ERROR_CHECK(httpd_register_uri_handler(http_server, &save));
    httpd_uri_t save_options{};
    save_options.uri = "/save"; save_options.method = HTTP_OPTIONS;
    save_options.handler = SaveOptionsHandler;
    ESP_ERROR_CHECK(httpd_register_uri_handler(http_server, &save_options));
    httpd_uri_t reset{};
    reset.uri = "/factory-reset"; reset.method = HTTP_POST; reset.handler = FactoryResetHandler;
    ESP_ERROR_CHECK(httpd_register_uri_handler(http_server, &reset));
    httpd_uri_t ota{};
    ota.uri = "/ota"; ota.method = HTTP_POST; ota.handler = OtaHandler;
    ESP_ERROR_CHECK(httpd_register_uri_handler(http_server, &ota));
    httpd_uri_t wildcard{};
    wildcard.uri = "/*"; wildcard.method = HTTP_GET; wildcard.handler = RedirectHandler;
    ESP_ERROR_CHECK(httpd_register_uri_handler(http_server, &wildcard));

    dns_running = true;
    xTaskCreate(DnsTask, "captive_dns", 4096, nullptr, 5, &dns_task);
    NotifyState();
    ESP_LOGI(kTag, "protected setup portal started");
}

void NetworkPortal::StopPortal() {
    if (!portal_active_.exchange(false)) return;
    ota_armed_ = false;
    {
        ScopedLock guard(state_lock_);
        ota_code_.clear();
        csrf_token_.clear();
    }
    if (ota_timer) esp_timer_stop(ota_timer);
    if (http_server) {
        httpd_stop(http_server);
        http_server = nullptr;
    }
    dns_running = false;
    if (dns_socket >= 0) {
        shutdown(dns_socket, SHUT_RDWR);
        close(dns_socket);
        dns_socket = -1;
    }
    esp_wifi_set_mode(WIFI_MODE_STA);
    NotifyState();
}

void NetworkPortal::ArmOta() {
    // Set the guard before enabling APSTA so a simultaneous GOT_IP event cannot
    // tear the portal down between StartPortal() and arming.
    ota_armed_ = true;
    StartPortal();
    char code[7];
    snprintf(code, sizeof(code), "%06lu", static_cast<unsigned long>(esp_random() % 1000000));
    {
        ScopedLock guard(state_lock_);
        ota_code_ = code;
    }
    if (!ota_timer) {
        esp_timer_create_args_t args{};
        args.callback = OtaTimeout;
        args.arg = this;
        args.name = "ota_window";
        ESP_ERROR_CHECK(esp_timer_create(&args, &ota_timer));
    } else {
        esp_timer_stop(ota_timer);
    }
    ESP_ERROR_CHECK(esp_timer_start_once(ota_timer, kOtaWindowSeconds * 1000000ULL));
    NotifyState();
    ESP_LOGW(kTag, "physical OTA window armed for %d seconds", kOtaWindowSeconds);
}
