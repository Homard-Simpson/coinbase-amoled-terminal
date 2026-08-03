#include "ota_coordination.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

namespace {
SemaphoreHandle_t firmware_update_gate = nullptr;
}

bool InitializeFirmwareUpdateGate() {
    if (firmware_update_gate) return true;
    firmware_update_gate = xSemaphoreCreateMutex();
    return firmware_update_gate != nullptr;
}

bool AcquireFirmwareUpdateGate(uint32_t timeout_ms) {
    if (!firmware_update_gate) return false;
    const TickType_t ticks = timeout_ms == UINT32_MAX
        ? portMAX_DELAY
        : pdMS_TO_TICKS(timeout_ms);
    return xSemaphoreTake(firmware_update_gate, ticks) == pdTRUE;
}

void ReleaseFirmwareUpdateGate() {
    if (firmware_update_gate) xSemaphoreGive(firmware_update_gate);
}
