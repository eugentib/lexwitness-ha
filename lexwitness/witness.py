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
import socket
import ssl
import sys
import threading
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
PROBE_DEADLINE_SECONDS = 5                 # total, including a server that drips its answer
EXCHANGE_DEADLINE_SECONDS = 8
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
        self.sequences = {}                  # 'node/boot' -> last accepted sequence (RAM only, never evicted)
        self.node_boots = {n: [] for n in NODES}  # boots seen per node, oldest first; only the last one is current
        self.public_node = None              # node last seen serving on the public path
        self.public_seen_at = None
        self.failures = 0
        self.last_probe_at = None            # last probe attempt (success or failure)
        self.first_probe_due = now + probe_offset
        self.planned_pause = None            # {'node','boot','until'}: public failures not counted against it
        self.next_probe = now + probe_offset
        self.report_seq = 0                  # increases with every report: a node refuses a replayed message

    # -- public path ------------------------------------------------------------------------------------------
    def observe(self, health, now):
        """Result of one public probe: parsed /health/ready, or None for a failed probe."""
        self.last_probe_at = now
        if isinstance(health, dict) and health.get('node') in NODES and health.get('serving') is True:
            self.public_node, self.public_seen_at, self.failures = health['node'], now, 0
        elif isinstance(health, dict) and 'node' not in health and health.get('ready') is True \
                and health.get('admission_paused') is False:
            self.failures = 0                # a release without node identity: up, but never attributed to a node
        else:
            self.failures += 1
        self.next_probe = now + (self.probe_interval if self.failures == 0 else PROBE_FAIL_SECONDS)

    def stale_after(self):
        return self.probe_interval + PUBLIC_FAILURES * PROBE_FAIL_SECONDS + 30

    def public_down(self, now=None):
        """Three failures in a row, or no probe at all for longer than a full failure cycle: a probe that stopped
        answering must not keep old health alive (review BACKUP)."""
        if self.failures >= PUBLIC_FAILURES:
            return True
        reference = self.last_probe_at if self.last_probe_at is not None else self.first_probe_due
        return now is not None and now - reference > self.stale_after()

    def public_fresh(self, now):
        """A recent successful probe that saw a node serving (a planned pause needs this, not just no failures)."""
        return self.failures == 0 and self.public_seen_at is not None and now - self.public_seen_at <= self.probe_interval + 30

    def serving(self, node, now=None):
        return self.public_node == node and not self.public_down(now)

    def report(self, now):
        live = self.lease if self.lease and self.lease['expires_at'] > now else None
        self.report_seq += 1
        return {'witness': self.id, 'witness_boot': self.boot, 'protocol': PROTOCOL, 'report_seq': self.report_seq,
                'quarantine_left': max(0, round(self.started + QUARANTINE_SECONDS - now, 1)),
                'public': {'node': self.public_node, 'failures': self.failures, 'down': self.public_down(now),
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
        # A node boot is current until a newer one is seen; older boots stay refused for the whole witness run (no
        # eviction: forged boots are impossible without the key, so the list only grows with real node reboots).
        boots = self.node_boots[node]
        if boot in boots and boot != boots[-1]:
            return refuse('retired-node-boot')
        key = node + '/' + boot
        if seq <= self.sequences.get(key, -1):
            return refuse('replayed-intent')
        if boot not in boots:
            boots.append(boot)
        self.sequences[key] = seq
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
        if self.public_down(now) and self.public_node == node and not paused:
            return refuse('not-serving-publicly')                       # the held lease is left to expire
        if not mine and self.serving(next(n for n in NODES if n != node), now):
            return refuse('other-node-serving')
        self.lease = {'node': node, 'boot': boot, 'expires_at': now + LEASE_SECONDS}
        # A pause is announced right after a fresh successful probe: renewals during the downtime can neither start
        # nor extend one, so a pause never lasts more than MAX_PLANNED_PAUSE_SECONDS of downtime.
        pause = intent.get('planned_pause_seconds')
        if self.public_fresh(now) and isinstance(pause, int) and not isinstance(pause, bool) \
                and 0 <= pause <= MAX_PLANNED_PAUSE_SECONDS:
            self.planned_pause = {'node': node, 'boot': boot, 'until': now + pause} if pause else None
        return {**answer, 'granted': True, 'lease_seconds': LEASE_SECONDS}


# -- transport ------------------------------------------------------------------------------------------------
def _with_deadline(work, seconds, abort, holder=None):
    """Runs work() with a total deadline; on expiry abort() unblocks it (socket shutdown) and TimeoutError is raised.
    `holder['thread']` exposes the worker, so a caller can refuse to start another while one is still alive."""
    result = {}

    def target():
        try:
            result['value'] = work()
        except BaseException as error:                                  # re-raised in the caller
            result['error'] = error
    thread = threading.Thread(target=target, daemon=True)
    if holder is not None:
        holder['thread'] = thread
    thread.start()
    thread.join(seconds)
    if thread.is_alive():
        abort()
        raise TimeoutError('deadline exceeded')
    if 'error' in result:
        raise result['error']
    return result.get('value')


def _connection(url, timeout):
    if url.scheme == 'https':
        return http.client.HTTPSConnection(url.hostname, url.port or 443, timeout=timeout, context=ssl.create_default_context())
    return http.client.HTTPConnection(url.hostname, url.port or 80, timeout=timeout)    # local tests only


def _shutdown(connection, response=None):
    """Unblocks a worker for real: with Connection: close http.client hands the socket to the response, so the
    response's socket is shut down too (review BACKUP: closing the connection alone left readers alive)."""
    raw = getattr(getattr(response, 'fp', None), 'raw', None)
    for sock in (getattr(connection, 'sock', None), getattr(raw, '_sock', None)):
        try:
            if sock is not None:
                sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    for closable in (response, connection):
        try:
            if closable is not None:
                closable.close()
        except Exception:
            pass


def probe(url, deadline=None):
    """GET the public health within PROBE_DEADLINE_SECONDS in total; None on any failure."""
    deadline = PROBE_DEADLINE_SECONDS if deadline is None else deadline
    parts = urllib.parse.urlsplit(url)
    connection, owned = _connection(parts, deadline), {}

    def work():
        connection.request('GET', (parts.path or '/') + ('?' + parts.query if parts.query else ''), headers={'user-agent': USER_AGENT})
        response = owned['response'] = connection.getresponse()
        body = response.read(65536)
        return json.loads(body) if response.status == 200 else None
    try:
        return _with_deadline(work, deadline, lambda: _shutdown(connection, owned.get('response')))
    except Exception:
        return None
    finally:
        connection.close()


class NodeLink:
    """One kept-alive HTTPS connection to a node's witness endpoint; reconnects once on a dropped connection
    (resending is harmless: the node only replies with its current intent)."""

    def __init__(self, endpoint, key):
        self.url, self.key, self.connection, self._token, self._worker = urllib.parse.urlsplit(endpoint), key, None, None, None

    def exchange(self, payload, timeout=5, deadline=None):
        """One signed exchange within EXCHANGE_DEADLINE_SECONDS in total (both attempts included). Each exchange owns
        its connection: a worker left behind by an expired deadline can never touch the next cycle's connection
        (review BACKUP: it closed the new one and posted on a third)."""
        deadline = EXCHANGE_DEADLINE_SECONDS if deadline is None else deadline
        if self._worker is not None and self._worker.is_alive():
            raise TimeoutError('previous exchange still unwinding')      # at most one lingering worker per link
        token = object()
        self._token = token
        owned = {'connection': self.connection}
        self.connection = None                                            # handed back only by a finished exchange
        try:
            holder = {}
            try:
                raw, connection = _with_deadline(lambda: self._exchange(payload, timeout, owned, token), deadline,
                                                 lambda: _shutdown(owned['connection'], owned.get('response')), holder)
            finally:
                self._worker = holder.get('thread')
        except TimeoutError:
            if self._token is token:
                self._token = None                                        # cancels the worker at its next step
            raise
        if self._token is token:
            self.connection = connection
        else:
            _shutdown(connection)
        reply = json.loads(raw)
        if not verify(self.key, reply.get('payload'), reply.get('signature')):
            raise ValueError('unsigned or tampered node reply')
        return reply['payload']

    def _exchange(self, payload, timeout, owned, token):
        body = canonical({'payload': payload, 'signature': sign(self.key, payload)})
        for attempt in (1, 2):
            if self._token is not token:
                raise TimeoutError('exchange cancelled')
            if owned['connection'] is None:
                owned['connection'] = _connection(self.url, timeout)
            connection = owned['connection']
            try:
                connection.request('POST', self.url.path or '/', body, {'content-type': 'application/json',
                                                                    'user-agent': USER_AGENT})
                response = owned['response'] = connection.getresponse()
                raw = response.read(262144)
                if response.status != 200:
                    raise ValueError('node answered ' + str(response.status))
                return raw, connection
            except (http.client.HTTPException, OSError):
                _shutdown(connection)
                owned['connection'] = None
                if attempt == 2:
                    raise


def log(message):
    print(time.strftime('%Y-%m-%d %H:%M:%S ') + message, flush=True)


def run(config_path):
    """The probe and each node link run in their own thread, so a slow or unreachable node never delays the public
    probe or the other node (review BACKUP: a serial loop stretched the 10/15 s cadence to 44/48 s)."""
    config = json.loads(Path(config_path).read_text())
    key = bytes.fromhex(config.get('key_hex') or '')
    single_instance(config.get('lock_path', '/run/lexwitness.lock'))
    endpoints = config.get('node_endpoints') or []
    if not str(config.get('id', '')).strip() or (endpoints and len(key) < 32):
        sys.exit('configuration: id is required, and key_hex (64 hex characters) when node_endpoints are set')
    witness = Witness(config['id'], time.monotonic(), float(config.get('probe_offset_seconds', 0)),
                      probe_interval=float(config.get('probe_interval_seconds', PROBE_OK_SECONDS)))
    lock, wake = threading.Lock(), threading.Event()
    log('witness ' + witness.id + ' boot ' + witness.boot + ', probe every ' + str(witness.probe_interval) + ' s, '
        + (str(len(endpoints)) + ' node endpoint(s)' if endpoints else 'observe only (no node endpoints)'))

    def probe_loop():
        last = None
        while True:
            with lock:
                delay = witness.next_probe - time.monotonic()
            if delay > 0:
                wake.wait(delay)
                wake.clear()
                continue
            health = probe(config['public_health_url'])                 # network I/O outside the lock
            with lock:
                witness.observe(health, time.monotonic())
                state = (witness.public_node, witness.failures > 0, witness.public_down())
                failures = witness.failures
            if state != last:
                last = state
                log('public path: ' + ('DOWN' if state[2] else 'failing' if state[1] else 'up')
                    + ' (node ' + str(state[0]) + ', failures ' + str(failures) + ')')

    def link_loop(endpoint):
        link, answer = NodeLink(endpoint, key), None
        while True:
            started = time.monotonic()
            try:
                with lock:
                    report = witness.report(time.monotonic())
                reply = link.exchange({'report': report, 'answer': answer})
                intent = reply.get('intent')
                with lock:
                    if reply.get('probe_now') is True:
                        witness.next_probe = min(witness.next_probe, time.monotonic())
                        wake.set()
                    answer = witness.handle(intent, time.monotonic()) if intent else None
            except Exception as error:                                  # the node is unreachable: retry next cycle
                answer = None
                log('exchange failed with ' + endpoint + ': ' + type(error).__name__)
            time.sleep(max(0.0, started + CYCLE_SECONDS - time.monotonic()))

    threads = [threading.Thread(target=probe_loop, daemon=True)]
    threads += [threading.Thread(target=link_loop, args=(endpoint,), daemon=True) for endpoint in endpoints]
    for thread in threads:
        thread.start()
    while all(thread.is_alive() for thread in threads):
        time.sleep(5)
    sys.exit('a witness thread stopped unexpectedly')                  # let the supervisor restart the witness


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='/etc/lexwitness/witness.json')
    run(parser.parse_args().config)
