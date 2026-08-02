#pragma once

#include <cstdint>

// Starts the V2-only background updater. The updater accepts only a strictly
// newer, stable V2 application named by a production-ready Ed25519-signed
// official release manifest. V1 does not compile or call this module.
void StartV2AutomaticOta();

// POWER standby takes this gate before stopping Wi-Fi. If an authenticated
// update is already being checked or written, standby waits up to timeout_ms
// and then stays awake rather than interrupting the inactive-slot write.
bool PauseV2AutomaticOtaForStandby(uint32_t timeout_ms);
void ResumeV2AutomaticOtaAfterStandby();
