# Privacy

Coinbase AMOLED Terminal is self-hosted software. The project does not operate a
hosted service, user-account system, analytics pipeline, advertising network, or
telemetry collector.

## Data the software may process

Depending on configuration, the local bridge may process:

- public market prices and timestamps;
- selected account totals;
- open-position symbol, side, size, entry price, and unrealized result;
- selected recent closed-position summaries;
- a device identifier and authentication result; and
- ordinary operational metadata such as request time, status, and source address.

This information can be financially sensitive even when it is not a conventional
identity field.

## Data flow

Coinbase credentials are read by the local bridge and used for read-only requests.
The bridge transforms and minimizes the response before serving the device feed.
The ESP does not need and must not receive the Coinbase credential. There is no
project-operated third-party relay.

By default, data should remain on the operator's bridge host and trusted local or
private-tailnet network. If an operator chooses a public reverse proxy, that
operator is responsible for access control, TLS, logging, retention, and legal
obligations.

## Storage and retention

- Bridge caches should be memory-resident and short-lived.
- Credential and feed-token files remain under operator control.
- Firmware may retain Wi-Fi and feed configuration in device NVS.
- Logs should contain status and timing only, not authorization values or complete
  portfolio payloads.
- Screenshots, crash dumps, serial logs, and support bundles may reveal data even
  when application logging is minimal.

The repository does not set a universal retention period because it does not host
operator data. Operators should retain only what they need and regularly remove
old logs, screenshots, artifacts, and backups.

## User controls

Operators can stop processing by shutting down the bridge, revoking the Coinbase
credential, rotating or deleting feed tokens, removing local cache/log files, and
erasing device NVS before disposal or transfer.

## Safe issue reporting

Before sharing a bug report:

1. replace account values with clearly synthetic examples;
2. remove authorization headers, credential IDs, tokens, device identifiers,
   addresses, hostnames, and Wi-Fi information;
3. crop or blur display screenshots; and
4. run `python3 scripts/scan_public_safety.py <path>` on the material.

The scanner checks UTF-8 text. It cannot prove that binaries, image pixels, image
metadata, archives, or deleted Git history are safe; review those separately.

Security reports should use the private process in [SECURITY.md](SECURITY.md).

## No sale or sharing by the project

Because the project does not operate a service or receive operator data, the
project maintainers do not sell or share that data. Third parties chosen by an
operator—such as a hosting provider, DNS provider, VPN, or log platform—have their
own terms and privacy practices.
