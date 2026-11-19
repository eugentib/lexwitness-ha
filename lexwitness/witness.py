#!/usr/bin/env python3
"""HA KISS witness (docs/ha-kiss-design.md, rule 2). Runs outside the platform's two machines (NAS, a Linux server, ...).

- Public path: checks https://api.lexassistant.ro/health/ready like a client, adaptively (every 60 s while it answers,
  every 10 s after a failure; witnesses stagger their start). Three failures in a row = "public path down".
- Lease: holds the PRIMARY lease, one at a time, 60 s. Granted only when no live lease exists and the other node is
  not seen serving; never renewed/granted to the node last seen serving while the public path is down (the existing
  lease is not cancelled, it expires). The holder may announce a planned pause (publication, restart; <= 15 min)
  during which public failures do not count against it.
- No disk state: after every start the witness grants and renews nothing for 75 s (lease + margin), so any lease
  given before it stopped has expired, however long it was down. A random witness_boot, required in every intent,
  makes messages from before a restart invalid; per-boot sequence numbers (RAM) refuse replays within a run.
- Probe on demand: a node may ask, in its reply, for an immediate probe (another witness saw a failure); a hint only
  triggers an observation, it never grants or refuses anything. With many witnesses the regular cadence can be slow.
- Transport: outbound only. Without node endpoints the witness only observes and logs (installation test). Every 15 s one signed POST per node endpoint (kept alive): the witness sends its report
  and the answer to the node's previous intent; the node replies with its current intent (hold | standby).
Standard library only, so it runs on a NAS or any Linux server without installing packages.
"""
import argparse
import fcntl
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import secrets
import ssl
import sys
import time
import urllib.parse
import urllib.request

PROTOCOL = 2
LEASE_SECONDS = 60
QUARANTINE_SECONDS = LEASE_SECONDS + 15
CYCLE_SECONDS = 15
PROBE_OK_SECONDS = 60
PROBE_FAIL_SECONDS = 10
PUBLIC_FAILURES = 3
MAX_PLANNED_PAUSE_SECONDS = 900
NODES = ('MAIN', 'BACKUP')
USER_AGENT = 'lexwitness/' + str(PROTOCOL)  # Cloudflare refuses the default Python-urllib agent (403)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sign(key, body):
    return hmac.new(key, canonical(body), hashlib.sha256).hexdigest()


def verify(key, body, signature):
    return isinstance(signature, str) and hmac.compare_digest(sign(key, body), signature)


def single_instance(lock_path):
    """One process per witness for its whole life: two instances under one identity could each grant a lease (review
    BACKUP, 19.11). The kernel drops the lock when the process dies, so a crash never leaves it stale."""
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise RuntimeError('another witness instance holds ' + str(lock_path)) from None
    return fd


class Witness:
    """The witness decisions, independent of transport and clocks (now = monotonic seconds since any origin)."""

    def __init__(self, witness_id, now, probe_offset=0.0, boot=None, probe_interval=PROBE_OK_SECONDS):
        self.id = witness_id
        self.probe_interval = probe_interval
        self.boot = boot or secrets.token_hex(8)
        self.started = now
        self.lease = None                    # {'node','boot','expires_at'}
        self.sequences = {}                  # 'node/boot' -> last accepted sequence (RAM only)
        self.public_node = None              # node last seen serving on the public path
        self.public_seen_at = None
        self.failures = 0
        self.planned_pause = None            # {'node','boot','until'}: public failures not counted against it
        self.next_probe = now + probe_offset

    # -- public path ------------------------------------------------------------------------------------------
    def observe(self, health, now):
        """Result of one public probe: parsed /health/ready, or None for a failed probe."""
        if isinstance(health, dict) and health.get('node') in NODES and health.get('serving') is True:
            self.public_node, self.public_seen_at, self.failures = health['node'], now, 0
        elif isinstance(health, dict) and 'node' not in health and health.get('ready') is True \
                and health.get('admission_paused') is False:
            self.failures = 0                # a release without node identity: up, but never attributed to a node
        else:
            self.failures += 1
        self.next_probe = now + (self.probe_interval if self.failures == 0 else PROBE_FAIL_SECONDS)

    def public_down(self):
        return self.failures >= PUBLIC_FAILURES

    def serving(self, node):
        return self.public_node == node and not self.public_down()

    def report(self, now):
        live = self.lease if self.lease and self.lease['expires_at'] > now else None
        return {'witness': self.id, 'witness_boot': self.boot, 'protocol': PROTOCOL,
                'quarantine_left': max(0, round(self.started + QUARANTINE_SECONDS - now, 1)),
                'public': {'node': self.public_node, 'failures': self.failures, 'down': self.public_down(),
                           'seen_ago': None if self.public_seen_at is None else round(now - self.public_seen_at, 1)},
                'planned_pause': None if not self.planned_pause or self.planned_pause['until'] <= now else
                                 {'node': self.planned_pause['node'], 'left': round(self.planned_pause['until'] - now, 1)},
                'lease': live and {'node': live['node'], 'expires_in': round(live['expires_at'] - now, 1)}}

    # -- lease ------------------------------------------------------------------------------------------------
    def handle(self, intent, now):
        """One node intent -> answer (signed by the transport together with the whole message)."""
        if not isinstance(intent, dict):
            intent = {}
        kind, node, boot, seq = (intent.get(k) for k in ('kind', 'node', 'boot', 'seq'))
        answer = {'kind': kind, 'node': node, 'boot': boot, 'seq': seq, 'witness': self.id, 'witness_boot': self.boot}

        def refuse(reason):
            return {**answer, 'granted': False, 'reason': reason}
        if kind not in ('hold', 'standby') or node not in NODES or not isinstance(boot, str) \
                or not isinstance(seq, int) or isinstance(seq, bool):
            return refuse('invalid-intent')
        if intent.get('witness_boot') != self.boot:
            return refuse('stale-witness-boot')
        key = node + '/' + boot
        if seq <= self.sequences.get(key, -1):
            return refuse('replayed-intent')
        self.sequences.pop(key, None)
        self.sequences[key] = seq                                       # most recent last; keep the last 16 boots
        for stale in list(self.sequences)[:-16]:
            del self.sequences[stale]
        held = self.lease if self.lease and self.lease['expires_at'] > now else None
        mine = bool(held and held['node'] == node and held['boot'] == boot)
        if kind == 'standby':
            if mine:
                self.lease = None
            return {**answer, 'granted': False, 'released': mine}
        if now - self.started < QUARANTINE_SECONDS:
            return refuse('witness-boot-quarantine')
        if held and not mine:
            return refuse('held-by-' + held['node'])
        paused = bool(self.planned_pause and self.planned_pause['node'] == node and self.planned_pause['boot'] == boot
                      and self.planned_pause['until'] > now)
        if self.public_down() and self.public_node == node and not paused:
            return refuse('not-serving-publicly')                       # the held lease is left to expire
        if not mine and self.serving(next(n for n in NODES if n != node)):
            return refuse('other-node-serving')
        self.lease = {'node': node, 'boot': boot, 'expires_at': now + LEASE_SECONDS}
        pause = intent.get('planned_pause_seconds')                     # announced while still serving, with a grant
        if isinstance(pause, int) and not isinstance(pause, bool) and 0 <= pause <= MAX_PLANNED_PAUSE_SECONDS:
            self.planned_pause = {'node': node, 'boot': boot, 'until': now + pause} if pause else None
        return {**answer, 'granted': True, 'lease_seconds': LEASE_SECONDS}


# -- transport ------------------------------------------------------------------------------------------------
def probe(url, timeout=4):
    try:
        request = urllib.request.Request(url, headers={'user-agent': USER_AGENT})
        with urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context()) as response:
            return json.loads(response.read(65536)) if response.status == 200 else None
    except Exception:
        return None


class NodeLink:
    """One kept-alive HTTPS connection to a node's witness endpoint; reconnects once on a dropped connection
    (resending is harmless: the node only replies with its current intent)."""

    def __init__(self, endpoint, key):
        self.url, self.key, self.connection = urllib.parse.urlsplit(endpoint), key, None

    def exchange(self, payload, timeout=10):
        body = canonical({'payload': payload, 'signature': sign(self.key, payload)})
        for attempt in (1, 2):
            if self.connection is None:
                self.connection = http.client.HTTPSConnection(self.url.hostname, self.url.port or 443,
                                                              timeout=timeout, context=ssl.create_default_context())
            try:
                self.connection.request('POST', self.url.path or '/', body, {'content-type': 'application/json',
                                                                         'user-agent': USER_AGENT})
                response = self.connection.getresponse()
                raw = response.read(262144)
                if response.status != 200:
                    raise ValueError('node answered ' + str(response.status))
                break
            except (http.client.HTTPException, OSError):
                self.connection.close()
                self.connection = None
                if attempt == 2:
                    raise
        reply = json.loads(raw)
        if not verify(self.key, reply.get('payload'), reply.get('signature')):
            raise ValueError('unsigned or tampered node reply')
        return reply['payload']


def log(message):
    print(time.strftime('%Y-%m-%d %H:%M:%S ') + message, flush=True)


def run(config_path):
    config = json.loads(Path(config_path).read_text())
    key = bytes.fromhex(config.get('key_hex') or '')
    single_instance(config.get('lock_path', '/run/lexwitness.lock'))
    endpoints = config.get('node_endpoints') or []
    if not str(config.get('id', '')).strip() or (endpoints and len(key) < 32):
        sys.exit('configuration: id is required, and key_hex (64 hex characters) when node_endpoints are set')
    witness = Witness(config['id'], time.monotonic(), float(config.get('probe_offset_seconds', 0)),
                      probe_interval=float(config.get('probe_interval_seconds', PROBE_OK_SECONDS)))
    links = {endpoint: NodeLink(endpoint, key) for endpoint in endpoints}
    log('witness ' + witness.id + ' boot ' + witness.boot + ', probe every ' + str(witness.probe_interval) + ' s, '
        + (str(len(links)) + ' node endpoint(s)' if links else 'observe only (no node endpoints)'))
    answers = dict.fromkeys(links)
    next_exchange, last_public = time.monotonic(), None
    while True:
        if time.monotonic() >= witness.next_probe:
            witness.observe(probe(config['public_health_url']), time.monotonic())
            after = (witness.public_node, witness.failures > 0, witness.public_down())
            if after != last_public:
                last_public = after
                log('public path: ' + ('DOWN' if after[2] else 'failing' if after[1] else 'up')
                    + ' (node ' + str(witness.public_node) + ', failures ' + str(witness.failures) + ')')
        if time.monotonic() >= next_exchange:
            next_exchange = time.monotonic() + CYCLE_SECONDS
            for endpoint, link in links.items():
                try:
                    reply = link.exchange({'report': witness.report(time.monotonic()), 'answer': answers[endpoint]})
                    if reply.get('probe_now') is True:
                        witness.next_probe = min(witness.next_probe, time.monotonic())
                    intent = reply.get('intent')
                    answers[endpoint] = witness.handle(intent, time.monotonic()) if intent else None
                except Exception as error:                              # the node is unreachable: retry next cycle
                    answers[endpoint] = None
                    log('exchange failed with ' + endpoint + ': ' + type(error).__name__)
        time.sleep(max(0.0, min(next_exchange, witness.next_probe) - time.monotonic()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='/etc/lexwitness/witness.json')
    run(parser.parse_args().config)
