#!/usr/bin/env python3
"""
S3Socks — SOCKS5 proxy tunneled through AWS S3 buckets
Based on proxyblob (quarkslab) architecture, adapted for S3.

Architecture:
  [Client App] <─SOCKS5─> [Proxy] <─── S3 Bucket ───> [Agent] <─TCP─> [Target]

The proxy runs a local SOCKS5 server.  Every CONNECT request is serialised
as binary packets and stored as S3 objects.  The agent polls S3, picks up
the requests, establishes the real TCP connections, and relays data back
through S3.  Both sides use adaptive polling so idle channels don't burn
API calls.

Usage:
  Proxy side (operator machine):
    python s3socks.py proxy -b <bucket> -r <region> [-l 127.0.0.1:1080]

  Agent side (target network):
    python s3socks.py agent -b <bucket> -r <region> -c <channel_id>

  Cleanup:
    python s3socks.py clean -b <bucket> -r <region> -c <channel_id>

Requirements:
    pip install boto3
Optional:
    pip install cryptography   # for AES-256-GCM payload encryption

AWS credentials: via env vars (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY),
                 ~/.aws/credentials, IAM role, or --profile.
"""

import argparse
import logging
import os
import queue
import secrets
import socket
import struct
import sys
import threading
import time
import uuid
from typing import Dict, List, Optional, Tuple

try:
    import boto3
    from botocore.config import Config as BotoConfig
    from botocore.exceptions import ClientError
except ImportError:
    print("[!] boto3 required: pip install boto3", file=sys.stderr)
    sys.exit(1)

# Optional AES-256-GCM encryption
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

log = logging.getLogger("s3socks")

# ═══════════════════════════════════════════════════════════════════
#  Protocol — binary packet format
# ═══════════════════════════════════════════════════════════════════
#
#  ┌──────────┬────────────────────┬────────────┬──────────────────┐
#  │ CMD (1B) │ ConnectionID (16B) │ Len (4B BE)│ Payload (0..1MB) │
#  └──────────┴────────────────────┴────────────┴──────────────────┘

CMD_NEW   = 0x01   # Proxy→Agent : open connection  (payload = ATYP+addr+port)
CMD_ACK   = 0x02   # Agent→Proxy : connection result (payload = 1B status, 0=ok)
CMD_DATA  = 0x03   # Bidirectional data relay
CMD_CLOSE = 0x04   # Bidirectional connection teardown
CMD_PING  = 0x05   # Keepalive / channel presence check

CMD_NAMES = {CMD_NEW: "NEW", CMD_ACK: "ACK", CMD_DATA: "DATA",
             CMD_CLOSE: "CLOSE", CMD_PING: "PING"}

HEADER_SIZE  = 21                 # 1 + 16 + 4
MAX_PKT_DATA = 1 * 1024 * 1024   # 1 MB

# SOCKS5 constants
SOCKS5_VER         = 0x05
SOCKS5_AUTH_NONE   = 0x00
SOCKS5_AUTH_USERPASS = 0x02
SOCKS5_AUTH_REJECT = 0xFF
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_ATYP_IPV4   = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_ATYP_IPV6   = 0x04

# Reply codes
SOCKS5_REP_OK                = 0x00
SOCKS5_REP_GENERAL_FAILURE   = 0x01
SOCKS5_REP_CONN_REFUSED      = 0x05
SOCKS5_REP_CMD_NOT_SUPPORTED = 0x07
SOCKS5_REP_ATYP_NOT_SUPPORTED = 0x08


class Packet:
    """Binary protocol packet (mirrors proxyblob's protocol.Packet)."""
    __slots__ = ('cmd', 'conn_id', 'data')

    def __init__(self, cmd: int, conn_id: bytes, data: bytes = b''):
        self.cmd     = cmd
        self.conn_id = conn_id   # 16 bytes
        self.data    = data

    def encode(self) -> bytes:
        return struct.pack('!B16sI', self.cmd, self.conn_id,
                           len(self.data)) + self.data

    @staticmethod
    def decode_stream(buf: bytes) -> Tuple[List['Packet'], bytes]:
        """Parse as many packets as possible; return (packets, leftover)."""
        packets = []
        off = 0
        while off + HEADER_SIZE <= len(buf):
            cmd, cid, dlen = struct.unpack_from('!B16sI', buf, off)
            if dlen > MAX_PKT_DATA:
                raise ValueError(f"packet data length {dlen} exceeds max")
            end = off + HEADER_SIZE + dlen
            if end > len(buf):
                break   # incomplete — keep remainder
            packets.append(Packet(cmd, cid, buf[off + HEADER_SIZE:end]))
            off = end
        return packets, buf[off:]

    def __repr__(self):
        cid_short = self.conn_id[:4].hex()
        return (f"Packet({CMD_NAMES.get(self.cmd, hex(self.cmd))}, "
                f"{cid_short}…, {len(self.data)}B)")


# ═══════════════════════════════════════════════════════════════════
#  Optional AES-256-GCM encryption
# ═══════════════════════════════════════════════════════════════════

class Encryptor:
    """Encrypts/decrypts blobs with AES-256-GCM derived from a password."""

    SALT = b's3socks-kdf-salt-v1'

    def __init__(self, password: str):
        if not HAS_CRYPTO:
            raise RuntimeError("pip install cryptography  (for encryption)")
        kdf = PBKDF2HMAC(algorithm=crypto_hashes.SHA256(),
                         length=32, salt=self.SALT, iterations=600_000)
        self._aesgcm = AESGCM(kdf.derive(password.encode()))

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        return nonce + self._aesgcm.encrypt(nonce, plaintext, None)

    def decrypt(self, blob: bytes) -> bytes:
        return self._aesgcm.decrypt(blob[:12], blob[12:], None)


# ═══════════════════════════════════════════════════════════════════
#  S3 Transport — bidirectional packet channel
# ═══════════════════════════════════════════════════════════════════

class S3Channel:
    """
    Multiplexed packet channel using an S3 prefix pair.

    proxy  writes  {channel}/c2a/*   reads  {channel}/a2c/*
    agent  writes  {channel}/a2c/*   reads  {channel}/c2a/*

    Each S3 object holds one or more concatenated encoded packets.
    Objects are deleted after successful consumption (FIFO queue).
    """

    def __init__(self, bucket: str, channel_id: str, role: str, *,
                 region: str = 'us-east-1', profile: str = None,
                 endpoint: str = None, encryptor: Encryptor = None):
        self.bucket    = bucket
        self.channel   = channel_id
        self.encryptor = encryptor

        if role == 'proxy':
            self.tx_prefix = f"{channel_id}/c2a/"
            self.rx_prefix = f"{channel_id}/a2c/"
        else:
            self.tx_prefix = f"{channel_id}/a2c/"
            self.rx_prefix = f"{channel_id}/c2a/"

        sess_kw = {}
        if profile:
            sess_kw['profile_name'] = profile
        session = boto3.Session(**sess_kw)

        cli_kw = {'region_name': region,
                   'config': BotoConfig(retries={'max_attempts': 3,
                                                  'mode': 'adaptive'},
                                        max_pool_connections=50)}
        if endpoint:
            cli_kw['endpoint_url'] = endpoint
        self.s3 = session.client('s3', **cli_kw)

        self._seq      = 0
        self._seq_lock = threading.Lock()
        self._tx_lock  = threading.Lock()

        # Stats
        self.tx_objects = 0
        self.rx_objects = 0
        self.tx_bytes   = 0
        self.rx_bytes   = 0

    # ── write ──────────────────────────────────────────────────
    def send(self, packets: List[Packet]):
        if not packets:
            return
        blob = b''.join(p.encode() for p in packets)
        if self.encryptor:
            blob = self.encryptor.encrypt(blob)
        key = self._next_key()
        with self._tx_lock:
            self.s3.put_object(Bucket=self.bucket, Key=key, Body=blob)
        self.tx_objects += 1
        self.tx_bytes   += len(blob)

    def _next_key(self) -> str:
        with self._seq_lock:
            ts  = int(time.time() * 1_000_000)
            self._seq += 1
            rnd = secrets.token_hex(4)
        return f"{self.tx_prefix}{ts:020d}_{self._seq:08d}_{rnd}.bin"

    # ── read ───────────────────────────────────────────────────
    def recv(self, max_keys: int = 100) -> List[Packet]:
        try:
            resp = self.s3.list_objects_v2(Bucket=self.bucket,
                                           Prefix=self.rx_prefix,
                                           MaxKeys=max_keys)
        except ClientError as e:
            log.warning("S3 list: %s", e)
            return []

        objs = resp.get('Contents', [])
        if not objs:
            return []

        objs.sort(key=lambda o: o['Key'])   # timestamp ordering

        all_pkts  = []
        to_delete = []

        for obj in objs:
            key = obj['Key']
            try:
                raw = self.s3.get_object(Bucket=self.bucket,
                                         Key=key)['Body'].read()
                if self.encryptor:
                    raw = self.encryptor.decrypt(raw)
                pkts, rem = Packet.decode_stream(raw)
                if rem:
                    log.debug("trailing %d bytes in %s", len(rem), key)
                all_pkts.extend(pkts)
                to_delete.append(key)
                self.rx_bytes += len(raw)
            except Exception as e:
                log.warning("S3 get %s: %s", key, e)

        # Batch delete (up to 1000 per request)
        self._delete_keys(to_delete)
        self.rx_objects += len(to_delete)
        return all_pkts

    def _delete_keys(self, keys: List[str]):
        if not keys:
            return
        # S3 delete_objects accepts up to 1000
        for i in range(0, len(keys), 1000):
            batch = keys[i:i+1000]
            try:
                self.s3.delete_objects(
                    Bucket=self.bucket,
                    Delete={'Objects': [{'Key': k} for k in batch],
                            'Quiet': True})
            except ClientError as e:
                log.warning("S3 batch delete: %s", e)

    # ── cleanup ────────────────────────────────────────────────
    def cleanup_channel(self):
        """Remove all objects under this channel's prefixes."""
        count = 0
        for pfx in [f"{self.channel}/c2a/", f"{self.channel}/a2c/"]:
            paginator = self.s3.get_paginator('list_objects_v2')
            for page in paginator.paginate(Bucket=self.bucket, Prefix=pfx):
                keys = [o['Key'] for o in page.get('Contents', [])]
                self._delete_keys(keys)
                count += len(keys)
        return count


# ═══════════════════════════════════════════════════════════════════
#  Adaptive Polling
# ═══════════════════════════════════════════════════════════════════

class AdaptiveSleep:
    """Sleep interval that shrinks when busy, grows when idle."""

    def __init__(self, min_s: float = 0.05, max_s: float = 2.0,
                 grow_factor: float = 1.3, shrink_factor: float = 0.5):
        self.min_s  = min_s
        self.max_s  = max_s
        self.grow   = grow_factor
        self.shrink = shrink_factor
        self.cur    = min_s

    def busy(self):
        self.cur = max(self.min_s, self.cur * self.shrink)

    def idle(self):
        self.cur = min(self.max_s, self.cur * self.grow)

    def sleep(self):
        time.sleep(self.cur)


# ═══════════════════════════════════════════════════════════════════
#  SOCKS5 Proxy Server (operator side)
# ═══════════════════════════════════════════════════════════════════

class ProxyServer:
    """
    Local SOCKS5 server that tunnels every CONNECT through S3.

    Flow per client connection:
      1. SOCKS5 handshake (auth negotiation + CONNECT request)
      2. Send CMD_NEW packet via S3 with target address
      3. Wait for CMD_ACK from agent
      4. Bidirectional relay: client TCP ←→ S3 packets
    """

    def __init__(self, channel: S3Channel,
                 host: str = '127.0.0.1', port: int = 1080,
                 socks_user: str = None, socks_pass: str = None):
        self.channel = channel
        self.host    = host
        self.port    = port
        self.socks_user = socks_user
        self.socks_pass = socks_pass

        # Connection tracking
        self.conns:      Dict[bytes, socket.socket]    = {}
        self.conn_evts:  Dict[bytes, threading.Event]  = {}
        self.conn_acks:  Dict[bytes, int]              = {}
        self._lock = threading.Lock()

        # Outbound packet queue (batched writes)
        self._tx_q: queue.Queue = queue.Queue()

        self.running    = False
        self.active     = 0   # active SOCKS sessions
        self._stats_ts  = time.time()

    # ── main ───────────────────────────────────────────────────
    def start(self):
        self.running = True

        # Background threads
        threading.Thread(target=self._rx_loop, daemon=True,
                         name="proxy-rx").start()
        threading.Thread(target=self._tx_loop, daemon=True,
                         name="proxy-tx").start()
        threading.Thread(target=self._stats_loop, daemon=True,
                         name="proxy-stats").start()

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(1.0)
        srv.bind((self.host, self.port))
        srv.listen(256)

        log.info("[proxy] SOCKS5 listening on %s:%d", self.host, self.port)
        if self.socks_user:
            log.info("[proxy] SOCKS5 auth: user/pass required")

        try:
            while self.running:
                try:
                    cli, addr = srv.accept()
                    threading.Thread(target=self._handle_client,
                                     args=(cli, addr), daemon=True).start()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            log.info("[proxy] shutting down…")
        finally:
            self.running = False
            srv.close()

    # ── SOCKS5 handshake ──────────────────────────────────────
    def _handle_client(self, cli: socket.socket, addr: tuple):
        cid = None
        try:
            cli.settimeout(30)

            # ── greeting ──
            buf = self._recv_exact(cli, 2)
            if not buf or buf[0] != SOCKS5_VER:
                return
            nmethods = buf[1]
            methods = self._recv_exact(cli, nmethods)
            if not methods:
                return

            # ── auth ──
            if self.socks_user:
                if SOCKS5_AUTH_USERPASS not in methods:
                    cli.sendall(bytes([SOCKS5_VER, SOCKS5_AUTH_REJECT]))
                    return
                cli.sendall(bytes([SOCKS5_VER, SOCKS5_AUTH_USERPASS]))
                # RFC 1929 user/pass sub-negotiation
                sub = self._recv_exact(cli, 2)
                if not sub or sub[0] != 0x01:
                    return
                ulen = sub[1]
                user = self._recv_exact(cli, ulen)
                plen_b = self._recv_exact(cli, 1)
                if not plen_b:
                    return
                pw = self._recv_exact(cli, plen_b[0])
                if (user and pw and
                    user.decode(errors='replace') == self.socks_user and
                    pw.decode(errors='replace') == self.socks_pass):
                    cli.sendall(bytes([0x01, 0x00]))  # success
                else:
                    cli.sendall(bytes([0x01, 0x01]))  # failure
                    return
            else:
                if SOCKS5_AUTH_NONE not in methods:
                    cli.sendall(bytes([SOCKS5_VER, SOCKS5_AUTH_REJECT]))
                    return
                cli.sendall(bytes([SOCKS5_VER, SOCKS5_AUTH_NONE]))

            # ── request ──
            hdr = self._recv_exact(cli, 4)
            if not hdr or hdr[0] != SOCKS5_VER:
                return
            cmd, _, atyp = hdr[1], hdr[2], hdr[3]

            if cmd != SOCKS5_CMD_CONNECT:
                self._socks_reply(cli, SOCKS5_REP_CMD_NOT_SUPPORTED)
                return

            # parse destination
            if atyp == SOCKS5_ATYP_IPV4:
                raw_addr = self._recv_exact(cli, 4)
                if not raw_addr:
                    return
                dst_addr = socket.inet_ntoa(raw_addr)
                addr_payload = bytes([SOCKS5_ATYP_IPV4]) + raw_addr
            elif atyp == SOCKS5_ATYP_DOMAIN:
                dlen_b = self._recv_exact(cli, 1)
                if not dlen_b:
                    return
                dlen = dlen_b[0]
                domain = self._recv_exact(cli, dlen)
                if not domain:
                    return
                dst_addr = domain.decode(errors='replace')
                addr_payload = bytes([SOCKS5_ATYP_DOMAIN, dlen]) + domain
            elif atyp == SOCKS5_ATYP_IPV6:
                raw_addr = self._recv_exact(cli, 16)
                if not raw_addr:
                    return
                dst_addr = socket.inet_ntop(socket.AF_INET6, raw_addr)
                addr_payload = bytes([SOCKS5_ATYP_IPV6]) + raw_addr
            else:
                self._socks_reply(cli, SOCKS5_REP_ATYP_NOT_SUPPORTED)
                return

            port_b = self._recv_exact(cli, 2)
            if not port_b:
                return
            dst_port = struct.unpack('!H', port_b)[0]
            addr_payload += port_b

            log.info("[proxy] CONNECT %s:%d from %s:%d",
                     dst_addr, dst_port, *addr)

            # ── send CMD_NEW via S3 ──
            cid = uuid.uuid4().bytes
            evt = threading.Event()
            with self._lock:
                self.conns[cid]     = cli
                self.conn_evts[cid] = evt
                self.active += 1

            self._tx_q.put(Packet(CMD_NEW, cid, addr_payload))

            # ── wait for ACK ──
            if not evt.wait(timeout=60):
                log.warning("[proxy] ACK timeout for %s:%d", dst_addr, dst_port)
                self._socks_reply(cli, SOCKS5_REP_GENERAL_FAILURE)
                self._drop(cid)
                return

            status = self.conn_acks.get(cid, 1)
            if status != 0:
                log.warning("[proxy] agent refused %s:%d (status=%d)",
                            dst_addr, dst_port, status)
                self._socks_reply(cli, SOCKS5_REP_CONN_REFUSED)
                self._drop(cid)
                return

            # ── success ──
            self._socks_reply(cli, SOCKS5_REP_OK)
            log.info("[proxy] tunnel open → %s:%d", dst_addr, dst_port)

            # relay client → S3
            cli.settimeout(0.3)
            while self.running:
                try:
                    data = cli.recv(65536)
                    if not data:
                        break
                    for off in range(0, len(data), MAX_PKT_DATA):
                        self._tx_q.put(Packet(CMD_DATA, cid,
                                              data[off:off+MAX_PKT_DATA]))
                except socket.timeout:
                    # check the connection is still tracked
                    with self._lock:
                        if cid not in self.conns:
                            break
                except (ConnectionResetError, ConnectionAbortedError,
                        BrokenPipeError, OSError):
                    break

        except Exception as e:
            log.debug("[proxy] client error: %s", e)
        finally:
            if cid:
                self._tx_q.put(Packet(CMD_CLOSE, cid))
                self._drop(cid)
            try:
                cli.close()
            except OSError:
                pass

    # ── S3 reader (agent → proxy) ─────────────────────────────
    def _rx_loop(self):
        poll = AdaptiveSleep(0.05, 2.0)
        while self.running:
            try:
                pkts = self.channel.recv()
                if not pkts:
                    poll.idle()
                    poll.sleep()
                    continue
                poll.busy()
                for p in pkts:
                    self._dispatch_rx(p)
            except Exception as e:
                log.error("[proxy] rx error: %s", e)
                time.sleep(1)

    def _dispatch_rx(self, p: Packet):
        if p.cmd == CMD_ACK:
            with self._lock:
                self.conn_acks[p.conn_id] = p.data[0] if p.data else 1
                evt = self.conn_evts.get(p.conn_id)
            if evt:
                evt.set()

        elif p.cmd == CMD_DATA:
            with self._lock:
                sock = self.conns.get(p.conn_id)
            if sock and p.data:
                try:
                    sock.sendall(p.data)
                except (BrokenPipeError, OSError):
                    self._tx_q.put(Packet(CMD_CLOSE, p.conn_id))
                    self._drop(p.conn_id)

        elif p.cmd == CMD_CLOSE:
            with self._lock:
                sock = self.conns.get(p.conn_id)
            if sock:
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
            self._drop(p.conn_id)

    # ── S3 writer (proxy → agent) ─────────────────────────────
    def _tx_loop(self):
        while self.running:
            batch = []
            try:
                batch.append(self._tx_q.get(timeout=0.05))
            except queue.Empty:
                continue

            # drain more without blocking
            batch_bytes = HEADER_SIZE + len(batch[0].data)
            while len(batch) < 100:
                try:
                    p = self._tx_q.get_nowait()
                    ps = HEADER_SIZE + len(p.data)
                    if batch_bytes + ps > 4 * 1024 * 1024:
                        # flush current, start new batch
                        self._flush_batch(batch)
                        batch = [p]
                        batch_bytes = ps
                        continue
                    batch.append(p)
                    batch_bytes += ps
                except queue.Empty:
                    break

            self._flush_batch(batch)

    def _flush_batch(self, batch: List[Packet]):
        if not batch:
            return
        try:
            self.channel.send(batch)
        except Exception as e:
            log.error("[proxy] tx error: %s", e)

    # ── helpers ────────────────────────────────────────────────
    def _socks_reply(self, cli: socket.socket, rep: int):
        cli.sendall(struct.pack('!BBBBIh', SOCKS5_VER, rep, 0x00,
                                SOCKS5_ATYP_IPV4, 0, 0))

    def _drop(self, cid: bytes):
        with self._lock:
            sock = self.conns.pop(cid, None)
            self.conn_evts.pop(cid, None)
            self.conn_acks.pop(cid, None)
            if sock:
                self.active -= 1
        if sock:
            try:
                sock.close()
            except OSError:
                pass

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
        buf = b''
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _stats_loop(self):
        while self.running:
            time.sleep(30)
            with self._lock:
                active = self.active
            log.info("[stats] active=%d  tx_obj=%d/%s  rx_obj=%d/%s",
                     active,
                     self.channel.tx_objects, _human(self.channel.tx_bytes),
                     self.channel.rx_objects, _human(self.channel.rx_bytes))


# ═══════════════════════════════════════════════════════════════════
#  Agent (target-network side)
# ═══════════════════════════════════════════════════════════════════

class Agent:
    """
    Polls S3 for proxy commands, opens real TCP connections in the
    target network, and relays data back through S3.
    """

    def __init__(self, channel: S3Channel, dns_server: str = None):
        self.channel    = channel
        self.dns_server = dns_server   # reserved for future use
        self.conns: Dict[bytes, socket.socket] = {}
        self._lock      = threading.Lock()
        self._tx_q: queue.Queue = queue.Queue()
        self.running    = False

    def start(self):
        self.running = True
        log.info("[agent] polling channel %s …", self.channel.channel)

        threading.Thread(target=self._tx_loop, daemon=True,
                         name="agent-tx").start()
        threading.Thread(target=self._stats_loop, daemon=True,
                         name="agent-stats").start()

        # Send an initial PING so the proxy knows we're alive
        self._tx_q.put(Packet(CMD_PING, b'\x00' * 16))

        poll = AdaptiveSleep(0.05, 2.0)
        try:
            while self.running:
                try:
                    pkts = self.channel.recv()
                    if not pkts:
                        poll.idle()
                        poll.sleep()
                        continue
                    poll.busy()
                    for p in pkts:
                        self._dispatch(p)
                except Exception as e:
                    log.error("[agent] poll error: %s", e)
                    time.sleep(1)
        except KeyboardInterrupt:
            log.info("[agent] shutting down…")
        finally:
            self.running = False
            self._close_all()

    # ── dispatcher ─────────────────────────────────────────────
    def _dispatch(self, p: Packet):
        if p.cmd == CMD_NEW:
            threading.Thread(target=self._handle_new, args=(p,),
                             daemon=True).start()
        elif p.cmd == CMD_DATA:
            self._handle_data(p)
        elif p.cmd == CMD_CLOSE:
            self._handle_close(p)
        elif p.cmd == CMD_PING:
            pass  # presence acknowledged

    # ── CMD_NEW: connect to target ─────────────────────────────
    def _handle_new(self, p: Packet):
        try:
            addr, port = self._parse_addr(p.data)
        except Exception as e:
            log.warning("[agent] bad address in NEW: %s", e)
            self._tx_q.put(Packet(CMD_ACK, p.conn_id, b'\x01'))
            return

        log.info("[agent] NEW → %s:%d", addr, port)
        try:
            sock = socket.create_connection((addr, port), timeout=15)
            sock.settimeout(0.3)
        except Exception as e:
            log.warning("[agent] connect failed %s:%d — %s", addr, port, e)
            self._tx_q.put(Packet(CMD_ACK, p.conn_id, b'\x01'))
            return

        with self._lock:
            self.conns[p.conn_id] = sock

        self._tx_q.put(Packet(CMD_ACK, p.conn_id, b'\x00'))
        log.info("[agent] connected %s:%d ✓", addr, port)

        # relay target → S3
        threading.Thread(target=self._relay_target, args=(p.conn_id, sock),
                         daemon=True).start()

    # ── CMD_DATA ───────────────────────────────────────────────
    def _handle_data(self, p: Packet):
        with self._lock:
            sock = self.conns.get(p.conn_id)
        if sock and p.data:
            try:
                sock.sendall(p.data)
            except (BrokenPipeError, OSError):
                self._tx_q.put(Packet(CMD_CLOSE, p.conn_id))
                self._drop(p.conn_id)

    # ── CMD_CLOSE ──────────────────────────────────────────────
    def _handle_close(self, p: Packet):
        log.debug("[agent] CLOSE %s", p.conn_id[:4].hex())
        self._drop(p.conn_id)

    # ── target → S3 relay ─────────────────────────────────────
    def _relay_target(self, cid: bytes, sock: socket.socket):
        try:
            while self.running:
                try:
                    data = sock.recv(65536)
                    if not data:
                        break
                    for off in range(0, len(data), MAX_PKT_DATA):
                        self._tx_q.put(Packet(CMD_DATA, cid,
                                              data[off:off+MAX_PKT_DATA]))
                except socket.timeout:
                    with self._lock:
                        if cid not in self.conns:
                            break
                    continue
                except (ConnectionResetError, BrokenPipeError, OSError):
                    break
        finally:
            self._tx_q.put(Packet(CMD_CLOSE, cid))
            self._drop(cid)

    # ── S3 writer ──────────────────────────────────────────────
    def _tx_loop(self):
        while self.running:
            batch = []
            try:
                batch.append(self._tx_q.get(timeout=0.05))
            except queue.Empty:
                continue

            batch_bytes = HEADER_SIZE + len(batch[0].data)
            while len(batch) < 100:
                try:
                    p = self._tx_q.get_nowait()
                    ps = HEADER_SIZE + len(p.data)
                    if batch_bytes + ps > 4 * 1024 * 1024:
                        self._flush(batch)
                        batch = [p]
                        batch_bytes = ps
                        continue
                    batch.append(p)
                    batch_bytes += ps
                except queue.Empty:
                    break
            self._flush(batch)

    def _flush(self, batch: List[Packet]):
        if not batch:
            return
        try:
            self.channel.send(batch)
        except Exception as e:
            log.error("[agent] tx error: %s", e)

    # ── helpers ────────────────────────────────────────────────
    @staticmethod
    def _parse_addr(data: bytes) -> Tuple[str, int]:
        atyp = data[0]
        if atyp == SOCKS5_ATYP_IPV4:
            addr = socket.inet_ntoa(data[1:5])
            port = struct.unpack('!H', data[5:7])[0]
        elif atyp == SOCKS5_ATYP_DOMAIN:
            dlen = data[1]
            addr = data[2:2+dlen].decode()
            port = struct.unpack('!H', data[2+dlen:4+dlen])[0]
        elif atyp == SOCKS5_ATYP_IPV6:
            addr = socket.inet_ntop(socket.AF_INET6, data[1:17])
            port = struct.unpack('!H', data[17:19])[0]
        else:
            raise ValueError(f"unknown ATYP {atyp:#x}")
        return addr, port

    def _drop(self, cid: bytes):
        with self._lock:
            sock = self.conns.pop(cid, None)
        if sock:
            try:
                sock.close()
            except OSError:
                pass

    def _close_all(self):
        with self._lock:
            socks = list(self.conns.values())
            self.conns.clear()
        for s in socks:
            try:
                s.close()
            except OSError:
                pass

    def _stats_loop(self):
        while self.running:
            time.sleep(30)
            with self._lock:
                n = len(self.conns)
            log.info("[stats] conns=%d  tx_obj=%d/%s  rx_obj=%d/%s",
                     n,
                     self.channel.tx_objects, _human(self.channel.tx_bytes),
                     self.channel.rx_objects, _human(self.channel.rx_bytes))


# ═══════════════════════════════════════════════════════════════════
#  Utilities
# ═══════════════════════════════════════════════════════════════════

def _human(b: int) -> str:
    for u in ('B', 'KB', 'MB', 'GB'):
        if b < 1024:
            return f"{b:.1f}{u}"
        b /= 1024
    return f"{b:.1f}TB"


BANNER = r"""
 ___  ____  ____             _
/ __)( __ \/ ___)  ___   ___| | __ ___
\__ \ (__ (\___ \ / _ \ / __| |/ // __|
(___/(____/(____/| (_) | (__|   < \__ \
                  \___/ \___|_|\_\|___/
  SOCKS5 proxy tunneled through AWS S3
  Based on proxyblob (quarkslab)
"""


# ═══════════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='S3Socks — SOCKS5 tunnel through AWS S3',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Proxy (generates channel ID, prints it for the agent)
  python s3socks.py proxy -b my-tunnel-bucket -r eu-west-1

  # Proxy with specific channel + encryption + SOCKS auth
  python s3socks.py proxy -b my-bucket -r us-east-1 -c ops42 \\
      --password s3cret --socks-user admin --socks-pass hunter2

  # Agent in the target network
  python s3socks.py agent -b my-bucket -r us-east-1 -c ops42 --password s3cret

  # Custom S3-compatible endpoint (MinIO / LocalStack)
  python s3socks.py proxy -b test -r us-east-1 --endpoint http://localhost:9000

  # Cleanup channel objects when done
  python s3socks.py clean -b my-bucket -r us-east-1 -c ops42
""")

    sub = parser.add_subparsers(dest='mode', required=True,
                                help='operation mode')

    # ── shared arguments ──
    def add_common(p):
        p.add_argument('-b', '--bucket', required=True,
                       help='S3 bucket name')
        p.add_argument('-r', '--region', default='us-east-1',
                       help='AWS region (default: us-east-1)')
        p.add_argument('-c', '--channel', default=None,
                       help='Channel ID (auto-generated for proxy)')
        p.add_argument('--profile', default=None,
                       help='AWS CLI profile for credentials')
        p.add_argument('--endpoint', default=None,
                       help='Custom S3 endpoint URL (MinIO, LocalStack…)')
        p.add_argument('-p', '--password', default=None,
                       help='AES-256-GCM encryption password')
        p.add_argument('-v', '--verbose', action='store_true',
                       help='Debug logging')

    # proxy
    p_proxy = sub.add_parser('proxy', help='Run local SOCKS5 proxy')
    add_common(p_proxy)
    p_proxy.add_argument('-l', '--listen', default='127.0.0.1:1080',
                         help='Listen address (default: 127.0.0.1:1080)')
    p_proxy.add_argument('--socks-user', default=None,
                         help='SOCKS5 username (enables user/pass auth)')
    p_proxy.add_argument('--socks-pass', default=None,
                         help='SOCKS5 password')

    # agent
    p_agent = sub.add_parser('agent', help='Run agent in target network')
    add_common(p_agent)

    # clean
    p_clean = sub.add_parser('clean', help='Delete all S3 objects in a channel')
    add_common(p_clean)

    args = parser.parse_args()

    # ── logging ──
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s %(message)s', datefmt='%H:%M:%S')

    print(BANNER)

    # ── encryption ──
    enc = None
    if args.password:
        if not HAS_CRYPTO:
            log.error("Encryption requires:  pip install cryptography")
            sys.exit(1)
        enc = Encryptor(args.password)
        log.info("[crypto] AES-256-GCM enabled")

    # ── channel id ──
    if args.mode == 'proxy' and not args.channel:
        args.channel = secrets.token_hex(8)

    if not args.channel:
        parser.error("--channel / -c is required for agent and clean modes")

    log.info("[channel] %s", args.channel)

    # ── dispatch ──
    if args.mode == 'proxy':
        chan = S3Channel(args.bucket, args.channel, 'proxy',
                         region=args.region, profile=args.profile,
                         endpoint=args.endpoint, encryptor=enc)
        host, port_s = args.listen.rsplit(':', 1)
        srv = ProxyServer(chan, host, int(port_s),
                          socks_user=args.socks_user,
                          socks_pass=args.socks_pass)
        log.info("[proxy] channel=%s  bucket=%s  region=%s",
                 args.channel, args.bucket, args.region)
        log.info("[proxy] start agent with:  python s3socks.py agent "
                 "-b %s -r %s -c %s%s",
                 args.bucket, args.region, args.channel,
                 f" -p <password>" if args.password else "")
        srv.start()

    elif args.mode == 'agent':
        chan = S3Channel(args.bucket, args.channel, 'agent',
                         region=args.region, profile=args.profile,
                         endpoint=args.endpoint, encryptor=enc)
        agent = Agent(chan)
        agent.start()

    elif args.mode == 'clean':
        chan = S3Channel(args.bucket, args.channel, 'proxy',
                         region=args.region, profile=args.profile,
                         endpoint=args.endpoint, encryptor=enc)
        n = chan.cleanup_channel()
        log.info("[clean] deleted %d objects from channel %s",
                 n, args.channel)


if __name__ == '__main__':
    main()
