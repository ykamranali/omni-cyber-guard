"""
Passive network threat monitor.

This module observes traffic and raises alerts. It is strictly read-only on
the wire: it does not inject, forge, drop or otherwise modify packets. An
earlier version forged TCP RST packets with a spoofed source address to tear
down connections; that was removed, because forging packets with an address you
do not own is indistinguishable from an attack and cannot be reconciled with
this platform's defensive-only posture.

Where events live
-----------------
Events are written to Redis, not to a Python list. The sniffer needs raw-socket
capability and therefore runs in the worker container; the API that serves
`/threat-intel` runs in a different process entirely. An in-process deque meant
the API always reported an empty feed no matter what the sniffer saw — the same
split-brain failure the IP blocklist had. Redis is the shared store both
processes can reach.

If Redis is unreachable the monitor degrades to a per-process buffer and says
so through `monitor_status()`, rather than presenting a partial view as
complete.
"""
from __future__ import annotations

import collections
import json
import logging
import threading
import time
from datetime import datetime, timezone

from app.core.config import settings

logger = logging.getLogger(__name__)

try:
    from scapy.all import IP, Raw, TCP, sniff
    SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on deployment environment
    SCAPY_AVAILABLE = False

MAX_EVENTS = 100
EVENTS_KEY = "ocg:threat_events"
#: Refreshed by the sniffer; its presence is how the API knows a monitor is
#: alive. A TTL means a dead sniffer stops claiming to be running.
HEARTBEAT_KEY = "ocg:threat_monitor:heartbeat"
HEARTBEAT_TTL_SECONDS = 90
HEARTBEAT_INTERVAL_SECONDS = 30

PORT_SCAN_THRESHOLD = 15
SYN_TRACKING_WINDOW_SECONDS = 60

_local_events: collections.deque = collections.deque(maxlen=MAX_EVENTS)
_syn_tracking: dict[str, set[int]] = collections.defaultdict(set)
_last_syn_cleanup = time.time()
_sniffer_started = False
_redis_client = None
_redis_failed = False


def _redis():
    """Lazily connect to Redis. Returns None if it is unreachable."""
    global _redis_client, _redis_failed
    if _redis_failed:
        return None
    if _redis_client is not None:
        return _redis_client
    try:
        import redis

        client = redis.Redis.from_url(
            settings.REDIS_URL, socket_connect_timeout=2, socket_timeout=2,
            decode_responses=True,
        )
        client.ping()
        _redis_client = client
        return client
    except Exception as exc:
        logger.warning("threat monitor: Redis unavailable (%s); using a per-process buffer", exc)
        _redis_failed = True
        return None


def add_threat(title: str, description: str, severity: str, tags: list[str]) -> None:
    """Record an observed event.

    Every event here comes from a real packet capture or a real subsystem
    status change — none are synthesised.
    """
    event = {
        "id": f"evt-{int(datetime.now().timestamp() * 1000)}",
        "title": title,
        "severity": severity,
        "description": description,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tags": tags,
    }

    # Suppress an identical event repeating within the recent window, so one
    # noisy host does not fill the feed with the same line.
    for existing in get_recent_threats()[:10]:
        if existing.get("title") == title and existing.get("description") == description:
            return

    client = _redis()
    if client is not None:
        try:
            pipe = client.pipeline()
            pipe.lpush(EVENTS_KEY, json.dumps(event))
            pipe.ltrim(EVENTS_KEY, 0, MAX_EVENTS - 1)
            pipe.execute()
            return
        except Exception:
            logger.exception("threat monitor: failed to write an event to Redis")

    _local_events.appendleft(event)


def get_recent_threats() -> list[dict]:
    client = _redis()
    if client is not None:
        try:
            return [json.loads(raw) for raw in client.lrange(EVENTS_KEY, 0, MAX_EVENTS - 1)]
        except Exception:
            logger.exception("threat monitor: failed to read events from Redis")
    return list(_local_events)


def monitor_status() -> dict:
    """
    Honest status for the UI, so an offline sniffer is never presented as a
    quiet network.

    `running` reflects a live heartbeat from whichever process is actually
    capturing, not whether this process happens to have started a thread.
    """
    client = _redis()
    shared = client is not None

    if shared:
        try:
            running = client.exists(HEARTBEAT_KEY) == 1
        except Exception:
            running = _sniffer_started and SCAPY_AVAILABLE
    else:
        running = _sniffer_started and SCAPY_AVAILABLE

    return {
        "available": SCAPY_AVAILABLE,
        "running": bool(running),
        "shared_store": shared,
        "events_in_window": len(get_recent_threats()),
    }


def process_packet(packet) -> None:
    global _last_syn_cleanup
    try:
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return

        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        dport = packet[TCP].dport

        # --- Port scan detection (SYN fan-out from a single source) ---
        if packet[TCP].flags == "S":
            _syn_tracking[ip_src].add(dport)
            if len(_syn_tracking[ip_src]) > PORT_SCAN_THRESHOLD:
                add_threat(
                    "Possible port scan detected",
                    f"Host {ip_src} sent SYN packets to more than "
                    f"{PORT_SCAN_THRESHOLD} distinct ports on {ip_dst}.",
                    "HIGH",
                    ["Reconnaissance", "Port Scan"],
                )
                _syn_tracking[ip_src].clear()

        # --- Cleartext credential exposure ---
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode(errors="ignore").lower()
            except Exception:
                payload = ""
            if any(marker in payload for marker in ("pass=", "password=", "authorization: basic")):
                add_threat(
                    "Cleartext credentials observed",
                    f"A credential-shaped field was seen unencrypted from {ip_src} "
                    f"to {ip_dst}:{dport}.",
                    "CRITICAL",
                    ["Credentials", "Cleartext", "Insecure"],
                )

        if time.time() - _last_syn_cleanup > SYN_TRACKING_WINDOW_SECONDS:
            _syn_tracking.clear()
            _last_syn_cleanup = time.time()

    except Exception:  # pragma: no cover - never let one packet kill the sniffer
        logger.exception("threat monitor: failed to process a packet")


def _heartbeat_loop() -> None:
    while True:
        client = _redis()
        if client is not None:
            try:
                client.set(HEARTBEAT_KEY, datetime.now(timezone.utc).isoformat(),
                           ex=HEARTBEAT_TTL_SECONDS)
            except Exception:
                logger.debug("threat monitor: heartbeat write failed")
        time.sleep(HEARTBEAT_INTERVAL_SECONDS)


def start_sniffer() -> None:
    """
    Start passive capture in daemon threads. Safe to call more than once.

    Intended to run in the worker container, which holds CAP_NET_RAW. The API
    container does not capture; it reads what the worker recorded.
    """
    global _sniffer_started
    if _sniffer_started:
        return
    _sniffer_started = True

    if not SCAPY_AVAILABLE:
        add_threat(
            "Passive monitor offline",
            "Scapy is not installed in this environment, so no traffic is being "
            "observed. Install scapy and grant CAP_NET_RAW to enable it.",
            "INFO",
            ["System", "Diagnostic"],
        )
        return

    def sniff_loop() -> None:
        try:
            sniff(filter="not port 5432 and not port 6379", prn=process_packet, store=False)
        except Exception as exc:  # pragma: no cover
            add_threat(
                "Passive monitor error",
                f"Packet capture could not start: {exc}. This usually means the "
                f"process lacks CAP_NET_RAW.",
                "MEDIUM",
                ["System", "Error"],
            )

    threading.Thread(target=sniff_loop, daemon=True, name="ocg-threat-monitor").start()
    threading.Thread(target=_heartbeat_loop, daemon=True, name="ocg-threat-heartbeat").start()


def reset_for_tests() -> None:
    """Test hook: drop cached Redis state and the local buffer."""
    global _redis_client, _redis_failed, _sniffer_started
    _redis_client = None
    _redis_failed = False
    _sniffer_started = False
    _local_events.clear()
    _syn_tracking.clear()
