set(terminal_sources
    "main.cc"
    "network_portal.cc"
    "runtime_config.cc"
    "config_validation.cc"
    "onboarding_metadata.cc"
    "ota_coordination.cc"
)

# Automatic release checks and libsodium remain V2-only. The coordinator above
# is shared so manual OTA and full standby are mutually exclusive on both boards.
set(terminal_private_requires "")
if(CONFIG_TERMINAL_BOARD_V2)
    list(APPEND terminal_sources "auto_ota_v2.cc")
    list(APPEND terminal_private_requires espressif__libsodium)
endif()

idf_component_register(
    SRCS ${terminal_sources}
    INCLUDE_DIRS "."
    REQUIRES
        app_update
        esp_event
        esp_hw_support
        esp_http_client
        esp_http_server
        esp_lcd
        esp_timer
        esp_wifi
        driver
        json
        mbedtls
        nvs_flash
        partition_table
    PRIV_REQUIRES ${terminal_private_requires}
)
