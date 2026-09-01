#!/usr/bin/env python3
"""Bounded packet ring and Suricata TLS-event flow extractor.

This is an experimental data-collection controller. It keeps a small tcpdump
ring buffer, receives EVE events over Suricata's Unix stream socket, and writes
the packets matching each TLS event's bidirectional five-tuple to a separate
PCAP together with its EVE JSON and a manifest.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import logging
import os
import pwd
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any


LOG = logging.getLogger("tls_capture_controller")


def detect_tpotce() -> Path:
    candidates: list[Path] = []
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            candidates.append(Path(pwd.getpwnam(sudo_user).pw_dir) / "tpotce")
        except KeyError:
            pass
    candidates.extend((Path.home() / "tpotce", Path("/opt/tpotce")))
    candidates.extend(Path("/home").glob("*/tpotce"))
    for candidate in candidates:
        if (candidate / "data/suricata/suricata.yaml").is_file():
            return candidate
    raise RuntimeError("T-Pot installation was not found")


def detect_capture_interface() -> str:
    """Use the host's default-route interface, falling back to all interfaces."""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            check=False, capture_output=True, text=True,
        )
        fields = result.stdout.split()
        if "dev" in fields:
            return fields[fields.index("dev") + 1]
    except (FileNotFoundError, IndexError):
        pass
    return "any"


def safe_component(value: Any) -> str:
    text = str(value if value is not None else "unknown")
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in text)


def parse_event_time(value: Any) -> dt.datetime:
    if not isinstance(value, str):
        return dt.datetime.now(dt.timezone.utc)
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return dt.datetime.now(dt.timezone.utc)


def merge_pcaps(parts: list[Path], destination: Path) -> int:
    """Merge compatible classic-PCAP files and return their packet count."""
    header: bytes | None = None
    endian = ""
    packet_count = 0
    with destination.open("wb") as output:
        for part in parts:
            with part.open("rb") as source:
                candidate = source.read(24)
                if len(candidate) != 24:
                    continue
                magic = candidate[:4]
                byte_order = {
                    b"\xd4\xc3\xb2\xa1": "<",
                    b"\xa1\xb2\xc3\xd4": ">",
                    b"\x4d\x3c\xb2\xa1": "<",
                    b"\xa1\xb2\x3c\x4d": ">",
                }.get(magic)
                if byte_order is None:
                    raise RuntimeError(f"Unsupported capture format in {part}")
                if header is None:
                    header, endian = candidate, byte_order
                    output.write(header)
                elif candidate != header or byte_order != endian:
                    raise RuntimeError("Capture parts use incompatible PCAP formats")

                while True:
                    record_header = source.read(16)
                    if not record_header:
                        break
                    if len(record_header) != 16:
                        raise RuntimeError(f"Truncated packet header in {part}")
                    captured_length = struct.unpack(f"{endian}IIII", record_header)[2]
                    packet = source.read(captured_length)
                    if len(packet) != captured_length:
                        raise RuntimeError(f"Truncated packet data in {part}")
                    output.write(record_header)
                    output.write(packet)
                    packet_count += 1
    if header is None:
        destination.unlink(missing_ok=True)
    return packet_count


class CaptureController:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.dataset = args.dataset.resolve()
        self.buffer_dir = self.dataset / "buffer"
        self.sessions_dir = self.dataset / "sessions"
        session_start = dt.datetime.now(dt.timezone.utc)
        self.session_id = session_start.strftime("%Y%m%dT%H%M%S.%fZ")
        self.started_at = session_start.isoformat()
        self.session_dir = self.sessions_dir / self.session_id
        self.flows_dir = self.session_dir / "flows"
        self.events_path = self.session_dir / "events.jsonl"
        self.manifest_path = self.session_dir / "manifest.jsonl"
        self.master_path = self.dataset / "master.json"
        for directory in (
            self.buffer_dir, self.sessions_dir, self.session_dir, self.flows_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)

        self.socket_path = args.socket_path
        self.server: socket.socket | None = None
        self.connection: socket.socket | None = None
        self.tcpdump: subprocess.Popen[str] | None = None
        self.stop_event = threading.Event()
        self.event_lock = threading.Lock()
        self.master_lock = threading.Lock()
        self.seen_flows: set[str] = set()
        self.tls_event_count = 0
        self.scheduled_flow_count = 0
        self.extracted_flow_count = 0
        self.extracted_packet_count = 0
        self.verified_handshake_count = 0
        self.failed_extraction_count = 0
        self.workers = concurrent.futures.ThreadPoolExecutor(
            max_workers=args.extract_workers,
            thread_name_prefix="flow-extractor",
        )
        self.output_uid = int(os.environ.get("SUDO_UID", os.getuid()))
        self.output_gid = int(os.environ.get("SUDO_GID", os.getgid()))
        for directory in (
            self.dataset, self.sessions_dir, self.session_dir, self.flows_dir,
        ):
            os.chown(directory, self.output_uid, self.output_gid)
        self.update_master("running")

    def give_to_invoking_user(self, *paths: Path) -> None:
        for path in paths:
            os.chown(path, self.output_uid, self.output_gid)

    def update_master(self, status: str) -> None:
        """Create or update this run's entry in dataset/master.json."""
        with self.master_lock:
            master: dict[str, Any] = {"schema_version": 1, "sessions": []}
            if self.master_path.exists():
                try:
                    loaded = json.loads(self.master_path.read_text(encoding="utf-8"))
                    if isinstance(loaded, dict) and isinstance(loaded.get("sessions"), list):
                        master = loaded
                except (OSError, json.JSONDecodeError):
                    LOG.warning("Existing master.json is invalid; creating a new index")
            entry = {
                "session_id": self.session_id,
                "started_at": self.started_at,
                "ended_at": None if status == "running" else dt.datetime.now(dt.timezone.utc).isoformat(),
                "status": status,
                "interface": self.args.interface,
                "ring_file_mb": self.args.ring_file_mb,
                "ring_files": self.args.ring_files,
                "tls_events": self.tls_event_count,
                "scheduled_flows": self.scheduled_flow_count,
                "extracted_flows": self.extracted_flow_count,
                "extracted_packets": self.extracted_packet_count,
                "verified_handshakes": self.verified_handshake_count,
                "failed_extractions": self.failed_extraction_count,
                "session_path": str(self.session_dir.relative_to(self.dataset)),
            }
            sessions = master["sessions"]
            if status == "running":
                interrupted_at = dt.datetime.now(dt.timezone.utc).isoformat()
                for existing in sessions:
                    if (
                        existing.get("session_id") != self.session_id
                        and existing.get("status") == "running"
                    ):
                        existing["status"] = "interrupted"
                        existing["ended_at"] = interrupted_at
            for index, existing in enumerate(sessions):
                if existing.get("session_id") == self.session_id:
                    sessions[index] = entry
                    break
            else:
                sessions.append(entry)
            temporary = self.master_path.with_name(f".master-{os.getpid()}.tmp")
            temporary.write_text(json.dumps(master, indent=2) + "\n", encoding="utf-8")
            temporary.replace(self.master_path)
            self.give_to_invoking_user(self.master_path)

    def start_tcpdump(self) -> None:
        prefix = self.buffer_dir / "ring.pcap"
        for old_file in self.buffer_dir.glob("ring.pcap*"):
            old_file.unlink()
        command = [
            "tcpdump", "-i", self.args.interface, "-nn", "-s", "0", "-U",
            "-C", str(self.args.ring_file_mb), "-W", str(self.args.ring_files),
            "-Z", "root", "-w", str(prefix),
        ]
        if self.args.capture_filter:
            command.extend(self.args.capture_filter.split())
        LOG.info("Starting bounded packet ring on interface %s", self.args.interface)
        self.tcpdump = subprocess.Popen(command, text=True)
        time.sleep(1)
        if self.tcpdump.poll() is not None:
            raise RuntimeError(f"tcpdump exited with status {self.tcpdump.returncode}")

    def prepare_socket(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if os.path.lexists(self.socket_path):
            mode = os.lstat(self.socket_path).st_mode
            if not stat.S_ISSOCK(mode):
                raise RuntimeError(f"Refusing to replace non-socket path: {self.socket_path}")
            self.socket_path.unlink()
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(self.socket_path))
        parent_gid = self.socket_path.parent.stat().st_gid
        os.chown(self.socket_path, -1, parent_gid)
        os.chmod(self.socket_path, 0o660)
        self.server.listen(1)
        self.server.settimeout(1)
        LOG.info("EVE socket ready at %s", self.socket_path)

    def restart_suricata(self) -> None:
        if self.args.no_restart:
            return
        LOG.info("Restarting container %s", self.args.container)
        result = subprocess.run(
            ["docker", "restart", self.args.container],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode:
            raise RuntimeError((result.stderr or result.stdout).strip())
        LOG.info("Suricata restarted")

    def archive_event(self, event: dict[str, Any]) -> None:
        with self.event_lock:
            with self.events_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event, separators=(",", ":")) + "\n")
            self.tls_event_count += 1
            self.give_to_invoking_user(self.events_path)

    def handle_event(self, event: dict[str, Any]) -> None:
        if event.get("event_type") != "tls":
            return
        required = ("src_ip", "dest_ip", "src_port", "dest_port")
        if any(event.get(field) is None for field in required):
            LOG.warning("Skipping TLS event without a complete five-tuple")
            return
        self.archive_event(event)
        identity = str(event.get("flow_id") or "|".join(str(event[k]) for k in required))
        with self.event_lock:
            if identity in self.seen_flows:
                return
            self.seen_flows.add(identity)
            self.scheduled_flow_count += 1
        LOG.info(
            "TLS event: %s:%s -> %s:%s (flow_id=%s)",
            event["src_ip"], event["src_port"], event["dest_ip"],
            event["dest_port"], event.get("flow_id", "unknown"),
        )
        self.workers.submit(self.extract_flow, event)

    def extract_flow(self, event: dict[str, Any]) -> None:
        # Event.wait() returns immediately during shutdown, unlike time.sleep().
        if self.stop_event.wait(self.args.post_seconds):
            return
        stamp = parse_event_time(event.get("timestamp")).astimezone(dt.timezone.utc)
        name = f"{stamp:%Y%m%dT%H%M%S.%fZ}_flow-{safe_component(event.get('flow_id'))}"
        destination = self.flows_dir / f"{name}.pcap"
        src, dst = event["src_ip"], event["dest_ip"]
        sport, dport = int(event["src_port"]), int(event["dest_port"])
        bpf = (
            f"tcp and ((src host {src} and src port {sport} and dst host {dst} "
            f"and dst port {dport}) or (src host {dst} and src port {dport} "
            f"and dst host {src} and dst port {sport}))"
        )

        with tempfile.TemporaryDirectory(prefix="tls-flow-") as temporary:
            temp_dir = Path(temporary)
            snapshots: list[Path] = []
            # Snapshot every retained ring segment. This preserves packets while
            # tcpdump continues rotating the live buffer.
            for index, source in enumerate(sorted(self.buffer_dir.glob("ring.pcap*"))):
                if self.stop_event.is_set():
                    return
                snapshot = temp_dir / f"source-{index}.pcap"
                try:
                    shutil.copy2(source, snapshot)
                    snapshots.append(snapshot)
                except OSError as exc:
                    LOG.warning("Could not snapshot %s: %s", source, exc)

            parts: list[Path] = []
            for index, snapshot in enumerate(snapshots):
                if self.stop_event.is_set():
                    return
                part = temp_dir / f"match-{index}.pcap"
                result = subprocess.run(
                    ["tcpdump", "-nn", "-r", str(snapshot), "-w", str(part), bpf],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0 and part.exists():
                    parts.append(part)
                elif result.returncode:
                    LOG.warning("Extraction failed for %s: %s", snapshot, result.stderr.strip())

            packet_count = merge_pcaps(parts, destination)

        if self.stop_event.is_set():
            destination.unlink(missing_ok=True)
            return

        handshake_verified = False
        if packet_count:
            syn_filter = "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn"
            syn_ack_filter = "tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)"
            syn = subprocess.run(
                ["tcpdump", "-nn", "-r", str(destination), "-c", "1", syn_filter],
                capture_output=True, text=True, check=False,
            )
            syn_ack = subprocess.run(
                ["tcpdump", "-nn", "-r", str(destination), "-c", "1", syn_ack_filter],
                capture_output=True, text=True, check=False,
            )
            handshake_verified = bool(syn.stdout.strip() and syn_ack.stdout.strip())

        manifest = {
            "schema_version": 1,
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "event_timestamp": event.get("timestamp"),
            "flow_id": event.get("flow_id"),
            "five_tuple": {
                "protocol": "tcp", "src_ip": src, "src_port": sport,
                "dest_ip": dst, "dest_port": dport,
            },
            "packet_count": packet_count,
            "pcap": str(destination.relative_to(self.dataset)) if packet_count else None,
            "handshake_verified": handshake_verified,
        }
        with self.event_lock:
            with self.manifest_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(manifest, separators=(",", ":")) + "\n")
            if packet_count:
                self.extracted_flow_count += 1
                self.extracted_packet_count += packet_count
                if handshake_verified:
                    self.verified_handshake_count += 1
            else:
                self.failed_extraction_count += 1
            self.give_to_invoking_user(self.manifest_path)
        if not self.stop_event.is_set():
            self.update_master("running")
        if packet_count:
            self.give_to_invoking_user(destination)
            LOG.info("Saved %d packets to %s", packet_count, destination)
        else:
            LOG.warning("No buffered packets matched TLS flow %s", event.get("flow_id"))

    def read_connection(self, connection: socket.socket) -> None:
        decoder = json.JSONDecoder()
        buffer = ""
        connection.settimeout(1)
        while not self.stop_event.is_set():
            try:
                data = connection.recv(65536)
            except socket.timeout:
                continue
            if not data:
                return
            buffer += data.decode("utf-8", errors="replace")
            while buffer:
                buffer = buffer.lstrip()
                try:
                    event, offset = decoder.raw_decode(buffer)
                except json.JSONDecodeError:
                    break
                buffer = buffer[offset:]
                if isinstance(event, dict):
                    self.handle_event(event)

    def run(self) -> None:
        self.start_tcpdump()
        self.prepare_socket()
        self.restart_suricata()
        LOG.info("Controller running; press Ctrl-C to stop")
        while not self.stop_event.is_set():
            try:
                assert self.server is not None
                self.connection, _ = self.server.accept()
                LOG.info("Suricata connected to the EVE socket")
                self.read_connection(self.connection)
            except socket.timeout:
                continue
            finally:
                if self.connection:
                    self.connection.close()
                    self.connection = None

    def stop(self) -> None:
        if self.stop_event.is_set():
            return
        self.stop_event.set()
        if self.connection:
            self.connection.close()
        if self.server:
            self.server.close()
        if self.tcpdump and self.tcpdump.poll() is None:
            self.tcpdump.send_signal(signal.SIGINT)
            try:
                self.tcpdump.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.tcpdump.terminate()
        # Cancel queued flows. Active workers observe stop_event at each stage.
        self.workers.shutdown(wait=True, cancel_futures=True)
        self.update_master("completed")
        if os.path.lexists(self.socket_path) and stat.S_ISSOCK(os.lstat(self.socket_path).st_mode):
            self.socket_path.unlink()
        cancelled = max(
            0,
            self.scheduled_flow_count
            - self.extracted_flow_count
            - self.failed_extraction_count,
        )
        LOG.info("=" * 60)
        LOG.info("TLS capture session summary")
        LOG.info("Session: %s", self.session_id)
        LOG.info("TLS events received: %d", self.tls_event_count)
        LOG.info("TLS flows scheduled: %d", self.scheduled_flow_count)
        LOG.info("Flows saved: %d", self.extracted_flow_count)
        LOG.info("Packets saved: %d", self.extracted_packet_count)
        LOG.info("Complete handshakes: %d/%d", self.verified_handshake_count, self.extracted_flow_count)
        LOG.info("Failed extractions: %d", self.failed_extraction_count)
        LOG.info("Cancelled during shutdown: %d", cancelled)
        LOG.info("Dataset: %s", self.session_dir)
        LOG.info("=" * 60)


def parse_args() -> argparse.Namespace:
    project_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(
        description="Capture a bounded packet ring and extract Suricata TLS flows"
    )
    parser.add_argument(
        "--interface", default="auto",
        help="capture interface (default: host default-route interface)",
    )
    parser.add_argument("--dataset", type=Path, default=project_dir / "dataset")
    parser.add_argument("--socket-path", type=Path, default=None)
    parser.add_argument("--container", default="suricata")
    parser.add_argument("--no-restart", action="store_true")
    parser.add_argument("--ring-file-mb", type=int, default=25)
    parser.add_argument("--ring-files", type=int, default=8)
    parser.add_argument("--post-seconds", type=float, default=3.0)
    parser.add_argument("--extract-workers", type=int, default=2)
    parser.add_argument(
        "--capture-filter", default="tcp",
        help="tcpdump capture filter for the ring (default: tcp)",
    )
    args = parser.parse_args()
    if args.interface == "auto":
        args.interface = detect_capture_interface()
    if args.socket_path is None:
        args.socket_path = detect_tpotce() / "data/suricata/log/eve.sock"
    if args.ring_file_mb < 1 or args.ring_files < 2 or args.post_seconds < 0:
        parser.error("ring size/count must be positive and post-seconds cannot be negative")
    return args


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = parse_args()
    if os.geteuid() != 0:
        LOG.error("Run this controller with sudo (raw packet capture requires root)")
        return 1
    if shutil.which("tcpdump") is None:
        LOG.error("tcpdump is required but was not found")
        return 1
    controller = CaptureController(args)
    try:
        controller.run()
    except KeyboardInterrupt:
        LOG.info("Stopping controller")
    except Exception as exc:
        LOG.error("Fatal error: %s", exc)
        return 1
    finally:
        controller.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
