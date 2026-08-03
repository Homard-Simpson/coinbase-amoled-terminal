#pragma once

// Starts the V2-only background updater. The updater accepts only a strictly
// newer, stable V2 application named by a production-ready Ed25519-signed
// official release manifest. V1 does not compile or call this module. Its
// checks and writes use the same exclusion gate as manual OTA and full standby.
void StartV2AutomaticOta();
