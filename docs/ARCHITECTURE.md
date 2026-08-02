# Architecture

## Goals

Coinbase AMOLED Terminal provides a glanceable, read-only display while keeping
financial credentials and high-detail account responses off the embedded device.
The design optimizes for:

- local ownership and operation;
- a small, auditable network surface;
- explicit separation between Coinbase credentials and device authentication;
- bounded, cacheable read traffic;
- fail-closed behavior for authentication and schema errors; and
- support for two electrically different display-board revisions.

Trading, transfers, withdrawals, hosted custody, and autonomous financial actions
are outside the architecture.

## System context

```mermaid
flowchart TB
    subgraph Coinbase[External service]
        API[Coinbase read-only API]
    end

    subgraph Host[Operator-controlled bridge host]
        Secret[(Credential file or local secret store)]
        Bridge[Read-only bridge]
        Cache[(Short-lived memory cache)]
        Proxy[TLS reverse proxy or private-tailnet ingress]
        Secret --> Bridge
        Bridge <--> Cache
        Bridge --> Proxy
    end

    subgraph Device[Trusted display network]
        ESP[ESP32-S3 firmware]
        NVS[(NVS: Wi-Fi, feed URL, scoped token)]
        ESP <--> NVS
    end

    API -->|authenticated GET/read operations| Bridge
    Proxy -->|minimal feed over HTTPS| ESP

    Operator[Operator] -->|local provisioning| Secret
    Operator -->|flash or private OTA| ESP
```

## Components

### Local bridge

The bridge is the only component permitted to access the Coinbase credential. It:

1. performs read-only API requests;
2. validates and normalizes upstream data;
3. reduces it to the fields required by the display;
4. caches results briefly to bound upstream traffic;
5. authenticates each display using a separate feed token; and
6. exposes health and minimal device-feed routes.

The bridge must not expose a generic Coinbase proxy. A route that accepts an
arbitrary upstream path, method, body, product, or account identifier would break
the security boundary even if its current caller uses only reads.

### Installer and localhost onboarding

The per-user installer is also the USB flasher and setup-session coordinator. It
verifies one versioned firmware manifest and each artifact digest, resolves the
board only from an exact accepted firmware hash or an explicit V1/V2 choice, and
writes a bounded one-time metadata envelope to a dedicated flash partition. It
does not erase unrelated NVS.

The onboarding HTTP server binds only to loopback. Captive-portal JavaScript sends
Coinbase JSON straight to that authenticated endpoint under exact Origin,
CORS/PNA, method, content-type, size, CSRF, expiry, and single-use controls. After
the read-only permission gate succeeds, it returns only safe device provisioning
values. The browser—not the bridge—then sends a separate allowlisted form to the
ESP. A same-computer localhost page is available when a captive mini-browser
blocks the direct request.

### Reverse proxy or private-tailnet ingress

The bridge process binds to loopback by default. Cross-host access should be
provided by one of:

- an HTTPS service reachable only within a private tailnet; or
- a tightly configured TLS reverse proxy with firewall and authentication policy.

The ingress layer terminates TLS, limits methods and paths, rate-limits requests,
and avoids logging authorization headers or response bodies. Public anonymous
exposure is not a supported deployment.

### ESP32 firmware

The firmware:

- stores only Wi-Fi configuration, a feed URL, a device identifier, and a scoped
  feed token;
- polls the fixed read-only feed route;
- validates HTTP status, size, schema version, types, and numeric bounds;
- renders last-known-good data with clear stale/offline states, bridge-local
  fixed-width 12-hour time, privacy mode, and muted chart-axis prices;
- selects V1 or V2 hardware support at build time;
- maps POWER short press to coordinated standby/wake and BOOT to the current blue
  action, privacy, or manual OTA based on exact hold duration; and
- on V2 only, periodically authenticates the production-ready latest release with
  the pinned Ed25519 manifest key and installs only a strictly newer stable V2
  application after signed size, SHA-256, project, version, and board checks.

POWER standby takes the V2 updater gate before pausing Wi-Fi, feed, touch, and
the panel. It waits or remains awake instead of interrupting an inactive-slot
write. V1 does not compile the automatic updater.

It never receives a Coinbase API key and has no code path for order or transfer
operations.

## Trust boundaries

| Boundary | Trusted side | Untrusted or less-trusted side | Required control |
| --- | --- | --- | --- |
| Coinbase API ↔ bridge | Bridge credential process | Internet and upstream responses | TLS verification, strict parsing, read-only scope |
| Secret storage ↔ bridge | Owner-readable local storage | Other host users and container layers | File permissions, read-only mount, no image copy |
| Bridge ↔ ingress | Loopback service | Proxy configuration and host network | Loopback bind, method/path allowlist |
| Ingress ↔ ESP | Private network endpoints | Network observers and lost devices | HTTPS, scoped token, ACL, rotation |
| USB flasher ↔ display hardware | Accepted manifest and explicit board identity | Ambiguous or wrong V1/V2 selection | Exact firmware-hash detection or no-default human choice; approved offsets only |
| Captive browser ↔ localhost onboarding | Short-lived loopback session | Captive portal and other browser origins | Exact Origin/CORS/PNA, bearer + CSRF binding, bounded single-use requests |
| Localhost onboarding ↔ ESP portal | Browser-held safe provisioning response | Any field that could contain a Coinbase key | Independent allowlisted `/save` form; unknown/duplicate/private-key fields rejected |
| Firmware ↔ display hardware | Selected board variant | Incorrect revision or electrical assumptions | Explicit build selector, clean dual builds, V2 compile guard against V1 rail writes, narrow shared PWRKEY IRQ allowlist |
| Display ↔ nearby people | Operator | Anyone with visual or physical access | Minimal data, privacy mode, POWER standby, NVS erase |

## Feed contract

The exact schema is versioned with the implementation. Its design rules are:

- top-level `schema_version` is mandatory;
- timestamps use UTC RFC 3339 form;
- every collection has a strict maximum length;
- unknown fields are ignored only when the schema version is compatible;
- required fields with wrong types reject the entire update;
- numbers must be finite and within display-safe bounds;
- strings are length-limited and rendered as text, never as format strings; and
- the bridge omits raw upstream objects and identifiers not used by the UI.

Illustrative shape, with placeholders rather than account data:

```json
{
  "schema_version": 1,
  "generated_at": "<UTC timestamp>",
  "refresh_seconds": "<bounded integer>",
  "summary": {
    "display_total": "<formatted optional value>",
    "display_result": "<formatted optional value>"
  },
  "assets": [
    {
      "symbol": "<allowlisted symbol>",
      "display_price": "<formatted value>",
      "position": "<optional minimized position object>"
    }
  ]
}
```

Formatting monetary values on the bridge can reduce the number of raw precision
details sent to the display. If the firmware needs numbers for charts, those
fields still require finite-value and range validation.

## Authentication model

There are two unrelated credentials:

| Credential | Stored on | Purpose | Required scope |
| --- | --- | --- | --- |
| Coinbase credential | Bridge host only | Read selected account data | View/read only |
| Device-feed token | Bridge and one ESP | Read the minimized feed | One route, one device, rotatable |

A feed token must never be accepted by Coinbase-facing code as an API credential.
Likewise, the bridge must never send its Coinbase credential in a device response.
Comparisons should be constant-time where practical, and authentication failures
should return a generic response without revealing whether a device identifier or
token was wrong.

## Request sequence

```mermaid
sequenceDiagram
    participant E as ESP32
    participant P as TLS ingress
    participant B as Local bridge
    participant C as Coinbase API

    E->>P: GET fixed feed path + scoped token
    P->>B: Forward allowed request over loopback
    B->>B: Authenticate device and inspect cache
    alt cache fresh
        B-->>P: Minimal cached payload
    else cache expired
        B->>C: Authenticated read request
        C-->>B: Account/market response
        B->>B: Validate, minimize, and cache
        B-->>P: Minimal payload
    end
    P-->>E: HTTPS response
    E->>E: Validate schema, atomically replace display state
```

## Failure behavior

- **Coinbase unavailable:** serve a clearly timestamped last-known-good cache only
  within a configured maximum age; otherwise return unavailable.
- **Bridge unavailable:** keep the previous frame and show stale/offline state.
- **Authentication failure:** do not serve cached portfolio data.
- **Malformed payload:** reject the complete update; never partially overwrite
  display state.
- **Clock or certificate failure:** fail TLS validation and surface a connection
  error rather than downgrading to insecure transport.
- **Wrong board variant:** stop and reflash the correct image; do not probe by
  issuing writes to both panel/PMU families.

## Deployment profiles

### Same-host development

Compose publishes the bridge on loopback. A local mock client can test it, but a
separate ESP cannot reach loopback directly.

### Trusted LAN

Keep the bridge on loopback and use an HTTPS reverse proxy bound to the LAN
interface. Restrict the host firewall to the display network. This is acceptable
only when the network is actively administered and the certificate is validated
by the ESP.

### Private tailnet (recommended for remote access)

Publish HTTPS only inside a private tailnet and use ACLs to allow the display or a
dedicated subnet router to reach the feed route. Do not enable a public funnel or
anonymous internet route.

## Build architecture

The firmware source is shared, but hardware-specific code is selected explicitly:

- `v1`: SH8601 display and FT5x06-family touch path, including required V1 power
  sequencing;
- `v2`: CO5300 display and CST816S/CST820-family touch path, avoiding V1-only PMU
  rail writes.

Both builds use only AXP2101 `0x41` bit-3 enable and `0x49 = 0x08` write-one-to-
clear at runtime for the physical PWRKEY short-press event. The allowlist cannot
address rail-control registers `0x80` through `0x99`.

CI builds both variants from clean state without credentials or per-device
provisioning. Release artifacts are board-specific and accompanied by a manifest
of offsets, sizes, SHA-256 digests, IDF version, and readiness/attestation flags.
The installer creates per-device values at runtime and puts only temporary session
metadata in the onboarding partition. CI artifacts are never production images
until the manifest controls and both real-hardware checklists are approved.

## Design decisions

### Why a bridge instead of direct Coinbase access?

An ESP is easier to lose, inspect, or extract than a maintained host. A bridge
keeps the high-value credential in a more controllable environment, narrows the
device protocol, centralizes rate limiting, and allows credential rotation without
replacing a Coinbase key in firmware.

### Why no trading endpoints?

Read-only display code does not need them. Adding them would radically increase
credential value, threat impact, testing burden, and regulatory/operational risk.
They are a permanent non-goal rather than a disabled feature flag.

### Why explicit board selection?

The revisions use different panel and touch controllers, and unsafe exploratory
writes can blank or destabilize a board. An explicit compile-time selector is
easier to audit than runtime guessing based on unique device information.
