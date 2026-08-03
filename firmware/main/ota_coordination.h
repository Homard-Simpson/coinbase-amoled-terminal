#pragma once

#include <cstdint>

// One cross-task exclusion boundary covers manual OTA, automatic V2 OTA, and
// battery-only full standby. The gate must be initialized before networking or
// updater tasks start; acquisition fails closed if initialization did not occur.
bool InitializeFirmwareUpdateGate();
bool AcquireFirmwareUpdateGate(uint32_t timeout_ms);
void ReleaseFirmwareUpdateGate();

class FirmwareUpdateGuard {
public:
    explicit FirmwareUpdateGuard(uint32_t timeout_ms)
        : locked_(AcquireFirmwareUpdateGate(timeout_ms)) {}
    ~FirmwareUpdateGuard() {
        if (locked_) ReleaseFirmwareUpdateGate();
    }

    FirmwareUpdateGuard(const FirmwareUpdateGuard&) = delete;
    FirmwareUpdateGuard& operator=(const FirmwareUpdateGuard&) = delete;

    bool locked() const { return locked_; }
    explicit operator bool() const { return locked_; }

private:
    bool locked_ = false;
};
