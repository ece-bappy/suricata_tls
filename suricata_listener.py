#!/usr/bin/env python3
"""
Suricata Eve Socket Listener
Reads JSON events from Suricata via Unix domain socket
Processes alert and TLS events
"""

import socket
import json
import os
import logging
import stat
import subprocess
import tempfile
import argparse
import pwd
from pathlib import Path
from typing import Dict, Any

# Configure logging
LOG_PATH = Path(tempfile.gettempdir()) / f"suricata_listener-{os.getuid()}.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class SuricataListener:
    """Listen to Suricata events from Unix socket"""
    
    def __init__(self, socket_path: str = None, tpotce_path: str = None):
        """
        Initialize the listener
        
        Args:
            socket_path: Path to the Unix socket; derived from T-Pot if omitted
            tpotce_path: Path to T-Pot installation (auto-detected if None)
        """
        self.server_socket = None
        self.connection = None
        self.connected = False
        self.event_count = 0
        self.alert_count = 0
        self.tls_count = 0
        
        # Auto-detect tpotce path if not provided
        if tpotce_path is None:
            self.tpotce_path = self._detect_tpotce_path()
        else:
            self.tpotce_path = tpotce_path

        if socket_path is None:
            socket_path = str(
                Path(self.tpotce_path) / "data" / "suricata" / "log" / "eve.sock"
            )
        self.socket_path = socket_path
        
        logger.info(f"Listener initialized with socket: {socket_path}")
        logger.info(f"T-Pot path: {self.tpotce_path}")
    
    def _detect_tpotce_path(self) -> str:
        """Auto-detect T-Pot installation path"""
        candidates = []

        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            try:
                candidates.append(Path(pwd.getpwnam(sudo_user).pw_dir) / "tpotce")
            except KeyError:
                pass

        candidates.extend((Path.home() / "tpotce", Path("/opt/tpotce")))
        candidates.extend(Path("/home").glob("*/tpotce"))

        for path in candidates:
            if (path / "data" / "suricata" / "suricata.yaml").is_file():
                return str(path)
        
        raise RuntimeError("T-Pot installation not found")
    
    def prepare_socket(self):
        """Create the Unix socket server before Suricata starts."""
        socket_path = Path(self.socket_path)
        socket_path.parent.mkdir(parents=True, exist_ok=True)

        if os.path.lexists(socket_path):
            mode = os.lstat(socket_path).st_mode
            if stat.S_ISSOCK(mode):
                socket_path.unlink()
                logger.info(f"Removed stale socket: {socket_path}")
            else:
                stale_path = socket_path.with_name(
                    f"{socket_path.name}.stale-{os.getpid()}"
                )
                socket_path.rename(stale_path)
                logger.warning(
                    f"Moved non-socket path out of the way: {socket_path} -> {stale_path}"
                )

        self.server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server_socket.bind(self.socket_path)

        # Match the socket group to its T-Pot log directory so the container's
        # unprivileged Suricata process can connect.
        parent_gid = socket_path.parent.stat().st_gid
        os.chown(self.socket_path, -1, parent_gid)
        os.chmod(self.socket_path, 0o660)
        self.server_socket.listen(1)
        logger.info(f"Listening on socket: {self.socket_path}")

    def restart_suricata(self, container_name: str = "suricata"):
        """Restart Suricata after the listening socket is ready."""
        logger.info(f"Restarting Docker container: {container_name}")
        try:
            result = subprocess.run(
                ["docker", "restart", container_name],
                check=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("Docker command not found") from exc
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or exc.stdout or str(exc)).strip()
            raise RuntimeError(f"Could not restart {container_name}: {detail}") from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Timed out restarting {container_name}") from exc

        logger.info(f"Container restarted: {result.stdout.strip() or container_name}")
    
    def disconnect(self):
        """Close connections and remove the listener-owned socket."""
        if self.connection:
            try:
                self.connection.close()
            except Exception as e:
                logger.error(f"Error closing connection: {e}")
            finally:
                self.connection = None
                self.connected = False

        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                logger.error(f"Error closing listener socket: {e}")
            finally:
                self.server_socket = None

        socket_path = Path(self.socket_path)
        if os.path.lexists(socket_path) and stat.S_ISSOCK(os.lstat(socket_path).st_mode):
            socket_path.unlink()
            logger.info(f"Removed socket: {socket_path}")
    
    def listen(self, restart_container: bool = True, container_name: str = "suricata"):
        """Serve EVE events, accepting Suricata connections and reconnections."""
        self.prepare_socket()
        if restart_container:
            self.restart_suricata(container_name)

        while True:
            logger.info("Waiting for Suricata to connect...")
            self.connection, _ = self.server_socket.accept()
            self.connected = True
            logger.info("Suricata connected")

            try:
                self._read_events()
            except (BrokenPipeError, ConnectionResetError):
                logger.warning("Suricata socket connection was lost")
            except Exception as e:
                logger.error(f"Error reading from socket: {e}")
            finally:
                self.connection.close()
                self.connection = None
                self.connected = False
                logger.info("Waiting for Suricata to reconnect")
    
    def _read_events(self):
        """Read and process events from the socket"""
        buffer = ""
        
        while self.connected:
            try:
                # Read data from socket
                data = self.connection.recv(65536).decode('utf-8', errors='ignore')
                
                if not data:
                    logger.warning("Socket closed by Suricata")
                    self.connected = False
                    break
                
                buffer += data
                
                # Process complete JSON objects in buffer
                while buffer:
                    # Find complete JSON object
                    try:
                        json_obj, remainder = self._extract_json(buffer)
                        if json_obj is None:
                            break
                        
                        buffer = remainder
                        self._process_event(json_obj)
                    
                    except json.JSONDecodeError as e:
                        logger.debug(f"JSON decode error: {e}")
                        break
            
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Error in event reading loop: {e}")
                raise
    
    def _extract_json(self, buffer: str) -> tuple:
        """
        Extract a complete JSON object from buffer
        
        Returns:
            Tuple of (json_dict, remaining_buffer) or (None, buffer) if incomplete
        """
        if not buffer:
            return None, buffer
        
        depth = 0
        in_string = False
        escape = False
        
        for i, char in enumerate(buffer):
            # Handle escape sequences
            if escape:
                escape = False
                continue
            
            if char == '\\' and in_string:
                escape = True
                continue
            
            # Handle string boundaries
            if char == '"' and not escape:
                in_string = not in_string
                continue
            
            # Count braces only outside strings
            if not in_string:
                if char == '{':
                    depth += 1
                elif char == '}':
                    depth -= 1
                    
                    # Found a complete JSON object
                    if depth == 0:
                        try:
                            json_str = buffer[:i+1]
                            json_obj = json.loads(json_str)
                            remaining = buffer[i+1:].lstrip()
                            return json_obj, remaining
                        except json.JSONDecodeError:
                            return None, buffer
        
        # No complete JSON object yet
        return None, buffer
    
    def _process_event(self, event: Dict[str, Any]):
        """Process a single event"""
        self.event_count += 1
        event_type = event.get('event_type', 'unknown')
        timestamp = event.get('timestamp', 'unknown')
        
        if event_type == 'alert':
            self._process_alert(event)
        elif event_type == 'tls':
            self._process_tls(event)
        else:
            logger.debug(f"Unhandled event type: {event_type}")
        
        # Log every 10 events
        if self.event_count % 10 == 0:
            logger.info(f"Events processed: {self.event_count} (Alerts: {self.alert_count}, TLS: {self.tls_count})")
    
    def _process_alert(self, event: Dict[str, Any]):
        """Process an alert event"""
        self.alert_count += 1
        
        timestamp = event.get('timestamp', 'N/A')
        src_ip = event.get('src_ip', 'N/A')
        dest_ip = event.get('dest_ip', 'N/A')
        src_port = event.get('src_port', 'N/A')
        dest_port = event.get('dest_port', 'N/A')
        
        alert = event.get('alert', {})
        signature = alert.get('signature', 'N/A')
        category = alert.get('category', 'N/A')
        severity = alert.get('severity', 'N/A')
        
        logger.info(
            f"ALERT: {signature} | "
            f"Severity: {severity} | Category: {category} | "
            f"{src_ip}:{src_port} → {dest_ip}:{dest_port}"
        )
        
        # Uncomment to log full event details
        # logger.debug(f"Full alert event: {json.dumps(event, indent=2)}")
    
    def _process_tls(self, event: Dict[str, Any]):
        """Process a TLS event"""
        self.tls_count += 1
        
        timestamp = event.get('timestamp', 'N/A')
        src_ip = event.get('src_ip', 'N/A')
        dest_ip = event.get('dest_ip', 'N/A')
        src_port = event.get('src_port', 'N/A')
        dest_port = event.get('dest_port', 'N/A')
        
        tls = event.get('tls', {})
        sni = tls.get('sni', 'N/A')
        version = tls.get('version', 'N/A')
        
        logger.info(
            f"TLS: {sni} | Version: {version} | "
            f"{src_ip}:{src_port} → {dest_ip}:{dest_port}"
        )
        
        # Uncomment to log full event details
        # logger.debug(f"Full TLS event: {json.dumps(event, indent=2)}")
    
    def show_stats(self):
        """Display event statistics"""
        logger.info("=" * 60)
        logger.info("Event Statistics")
        logger.info("=" * 60)
        logger.info(f"Total events: {self.event_count}")
        logger.info(f"Alerts: {self.alert_count}")
        logger.info(f"TLS events: {self.tls_count}")
        logger.info("=" * 60)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Receive Suricata EVE events over a Unix socket")
    parser.add_argument(
        "socket_path",
        nargs="?",
        default=None,
        help="host path for the EVE Unix socket (auto-detected by default)",
    )
    parser.add_argument(
        "--container",
        default="suricata",
        help="Docker container to restart after binding the socket (default: suricata)",
    )
    parser.add_argument(
        "--no-restart",
        action="store_true",
        help="do not restart the Suricata container",
    )
    args = parser.parse_args()
    listener = SuricataListener(args.socket_path)

    logger.info("Starting Suricata Event Listener")
    logger.info(f"Socket path: {listener.socket_path}")
    logger.info(f"Log path: {LOG_PATH}")
    
    try:
        listener.listen(
            restart_container=not args.no_restart,
            container_name=args.container,
        )
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        listener.disconnect()
        listener.show_stats()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        listener.disconnect()
        raise SystemExit(1)


if __name__ == "__main__":
    main()
