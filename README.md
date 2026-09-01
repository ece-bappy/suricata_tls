# Real-time Malicious TLS Traffic Dataset Collector for T-Pot CE

This repository implements the data-collection stage of the research project **“Real-time Malicious TLS Traffic Detection using Machine Learning Classifiers.”** It integrates with Suricata in T-Pot CE and collects complete TLS flows for later feature extraction, labeling, and machine-learning experiments.

The collector is designed to reduce disk usage. It keeps a bounded temporary TCP packet buffer and permanently saves only flows that Suricata identifies as TLS.

## Research objective

The wider research platform will passively inspect encrypted traffic at a network edge, derive observable TLS and flow characteristics, and use machine-learning classifiers to distinguish malicious and benign traffic. This implementation focuses only on reliable dataset acquisition; classification and traffic filtering are future stages.

The implementation does not decrypt TLS, alter payloads, or perform man-in-the-middle interception.

## System design

```text
                         +------------------------+
Network traffic -------->| bounded tcpdump buffer |----+
                         +------------------------+    |
                                                       | matching packets
Network traffic --------> Suricata                     |
                              |                        |
                              | TLS EVE event          |
                              v                        v
                         eve.sock ------------> Python controller
                                                   |
                                                   v
                                      timestamped dataset session
```

The packet buffer begins recording before Suricata reports an event. When a TLS EVE event arrives, the controller uses its bidirectional five-tuple (source and destination addresses, ports, and TCP protocol) to recover the complete flow from the buffer. This includes packets that preceded TLS recognition, such as the TCP `SYN`, `SYN-ACK`, and TLS handshake.

Suricata's native conditional `tag` capture was also tested. It captured packets only after TLS detection and therefore did not preserve the beginning of the connection. The bounded-buffer controller is the recommended dataset workflow.

## Core implementation

### `configure_suricata.sh`

This script prepares Suricata for dataset collection. It:

- Finds T-Pot automatically instead of using a machine-specific path.
- Changes EVE to `unix_stream` so events are delivered in real time.
- Enables only the requested EVE event types; the recommended dataset setting is `tls`.
- Changes only the relevant YAML sections instead of globally replacing keys.
- Finds and restarts the active Suricata container.
- Displays the current EVE and PCAP configuration with `--show`.
- Restores the original YAML from the T-Pot Git checkout with `--restore`.
- Supports Suricata's native conditional PCAP mode for experimentation, although that mode is not used by the recommended complete-flow collector.

### `tls_capture_controller.py`

This is the main program of the project. Running it starts a complete TLS dataset-collection session.

Its responsibilities are:

1. Detect the T-Pot installation and host capture interface.
2. Start `tcpdump` before Suricata generates events, creating a bounded rotating TCP buffer.
3. Create the `eve.sock` Unix stream server expected by the configured Suricata EVE output.
4. Restart Suricata only after the socket is ready.
5. Receive and store TLS EVE metadata in `events.jsonl`.
6. Deduplicate flow-extraction requests using Suricata's `flow_id`.
7. Wait briefly for packets following the TLS event.
8. Match both directions of the event's TCP five-tuple against every retained buffer segment.
9. Merge the matching packets into one flow-specific PCAP.
10. Verify that the PCAP contains a TCP `SYN` and `SYN-ACK`.
11. Append the flow metadata and verification result to `manifest.jsonl`.
12. Update the dataset-wide `master.json` session index.
13. Cancel pending work, finalize the session, and print a summary when `Ctrl+C` is pressed.

`suricata_listener.py` and `test_listener.sh` were created as small debugging utilities while testing EVE socket communication. They are not part of the dataset workflow and must not run alongside `tls_capture_controller.py` because the programs cannot share ownership of `eve.sock`.

## Requirements

- A T-Pot CE Git installation, normally at `$HOME/tpotce`
- A running Suricata Docker container named `suricata`
- Bash, Python 3.10 or newer, and `tcpdump`
- Root privileges for raw capture and the T-Pot socket directory

No third-party Python package or Scapy installation is required. The scripts search the invoking sudo user's home, the current user's home, `/opt/tpotce`, and `/home/*/tpotce` for a valid installation.

## Installation

```bash
git clone https://github.com/ece-bappy/suricata_tls.git
cd suricata_tls
chmod +x configure_suricata.sh tls_capture_controller.py
```

## Recommended workflow

The following commands are the complete procedure for collecting a TLS dataset.

### 1. Configure TLS-only EVE output

```bash
./configure_suricata.sh --filetype unix_stream --events tls
```

This configures Suricata to send TLS EVE records to `<tpotce>/data/suricata/log/eve.sock`.

If the earlier native conditional-PCAP experiment is enabled, disable it to prevent a second set of captures being written into T-Pot's log directory:

```bash
./configure_suricata.sh --tls-pcap disable
```

### 2. Start a collection session

```bash
sudo ./tls_capture_controller.py
```
Important: It takes 40-70 seconds before final logging starts.

By default, the controller:

- Detects the host's default-route interface.
- Keeps eight rotating packet-buffer files of 25 MB each.
- Captures TCP in the temporary buffer.
- Waits three seconds after a TLS event for later flow packets.
- Uses two extraction workers.
- Restarts Suricata after creating `eve.sock`.

Generate or receive TLS traffic while the controller is running.

For a simple functional test from another terminal:

```bash
for i in {1..100}; do curl -s -o /dev/null https://google.com; done
```

This traffic is only a collection test and should not be treated as malicious/benign training ground truth. The honeypot experiment must supply reliable labels for the final dataset.

### 3. Stop and review the session

Press `Ctrl+C`. Queued work is cancelled for immediate shutdown, `master.json` is updated, and a summary is displayed:

```text
TLS events received: 31
TLS flows scheduled: 31
Flows saved: 29
Packets saved: 1776
Complete handshakes: 29/29
Failed extractions: 0
Cancelled during shutdown: 2
```

Cancelled flows are not corrupt or failed captures; they had not completed their post-event wait or extraction. To retain the final flows, wait at least the configured post-event interval after traffic stops before pressing `Ctrl+C`.

## Dataset organization

Every controller run creates one timestamped session:

```text
dataset/
├── master.json
├── buffer/
│   └── ring.pcap0 ... ring.pcap7
└── sessions/
    └── 20260901T090352.363992Z/
        ├── events.jsonl
        ├── manifest.jsonl
        └── flows/
            ├── <timestamp>_flow-<flow_id>.pcap
            └── ...
```

### `buffer/`

Temporary full-TCP ring used to recover packets preceding the TLS event. It is cyclically overwritten and bounded to approximately 200 MB with the defaults. It is not permanent dataset output.

### `events.jsonl`

All Suricata TLS EVE records received during one session, with one JSON object per line.

### `manifest.jsonl`

One compact record per extracted flow, containing its Suricata flow ID, event time, five-tuple, packet count, relative PCAP path, and handshake-verification result.

### `flows/`

One PCAP per TLS flow. Separate files preserve a natural one-flow-per-sample format for ML, while the enclosing session makes an experiment easy to transfer, label, archive, or delete.

### `master.json`

Dataset-level index containing session times, status, capture settings, event and flow counts, packet totals, verified handshakes, failures, and paths. A previous session still marked `running` is marked `interrupted` when the next session starts.

Generated dataset content is excluded by `dataset/.gitignore` because PCAPs may be large and sensitive. Scripts and documentation belong in Git; production captures should use controlled research storage, a NAS, or an object store.

## Controller options

```bash
sudo ./tls_capture_controller.py \
    --interface eno2 \
    --ring-file-mb 25 \
    --ring-files 8 \
    --post-seconds 3 \
    --extract-workers 2
```

| Option | Purpose | Default |
|---|---|---:|
| `--interface` | Host capture interface | Default-route interface |
| `--dataset` | Dataset root | `./dataset` |
| `--socket-path` | Host EVE socket | Auto-detected |
| `--container` | Suricata container | `suricata` |
| `--no-restart` | Skip automatic restart | Disabled |
| `--ring-file-mb` | Size of each temporary segment | `25` |
| `--ring-files` | Number of retained segments | `8` |
| `--post-seconds` | Post-event wait | `3` |
| `--extract-workers` | Concurrent extractors | `2` |
| `--capture-filter` | Buffer BPF filter | `tcp` |

Increasing the ring capacity improves tolerance during high traffic but consumes more temporary disk. Permanent session data grows until collection stops, so production retention must be managed separately.

## Configuration and recovery

Show the current configuration:

```bash
./configure_suricata.sh --show
```

Enable TLS and alert events for debugging:

```bash
./configure_suricata.sh --filetype unix_stream --events tls,alert
```

Restore the original Suricata configuration:

```bash
./configure_suricata.sh --restore
```

Restoration copies `<tpotce>/docker/suricata/dist/suricata.yaml` to the live configuration. It does not rely on potentially modified backup files.

## Validation results

The implementation was validated on a live T-Pot CE deployment with Suricata 8.0.3. In one test, all 141 extracted flows had matching EVE metadata and flow IDs, consistent packet counts and five-tuples, a TCP `SYN`, and a corresponding `SYN-ACK`.

In a later session, the controller reported 29 saved flows, 1,776 permanent packets, 29 of 29 complete handshakes, no extraction failures, and zero kernel packet drops. These are functional checks, not performance benchmarks.

## Disk-consumption strategy

The design reduces storage through three controls:

1. Suricata emits only TLS EVE events in the recommended configuration.
2. General TCP packets exist only in a fixed-size rotating buffer.
3. Only Suricata-confirmed TLS flows enter permanent session storage.

The temporary buffer must include non-TLS TCP because the protocol is unknown before inspection. Permanent PCAPs can include encrypted application-data packets belonging to the confirmed TLS flow; payloads remain encrypted.

With the defaults, temporary storage is limited to approximately `8 × 25 MB = 200 MB`. Permanent storage contains one PCAP per confirmed TLS flow plus two compact JSONL files per session; it does not store permanent PCAPs for unrelated TCP flows.

## Current status

The data-collection prototype is implemented and live-tested. It captures pre-event and post-event packets for Suricata-identified TLS flows, verifies complete TCP handshakes, bounds temporary storage, organizes experiments into indexed sessions, and stops with an immediate summary. Dataset labeling, feature engineering, model training, evaluation, and real-time filtering remain future work.

## References

- [T-Pot CE](https://github.com/telekom-security/tpotce)
- [Suricata EVE JSON output](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html)
- [Suricata PCAP logging](https://docs.suricata.io/en/latest/output/pcap-log.html)
