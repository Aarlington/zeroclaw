#!/usr/bin/env python3
"""Disposable real-IdP CLI/WSS acceptance. Run only on an isolated Linux host.

Credentials, tokens, provider volumes and browser state stay in the temporary
fixture. Artifacts contain named assertions and image identities, never raw
provider/daemon output. This is a manual acceptance harness, not production CI.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from playwright.sync_api import sync_playwright
from websockets.sync.client import connect


class CheckError(Exception):
    pass


class LocalConnection:
    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(15)
        self.socket.connect(str(path))
        self.reader = self.socket.makefile('rb')

    def send(self, text):
        self.socket.sendall(text.encode() + b'\n')

    def recv(self, timeout):
        self.socket.settimeout(timeout)
        return self.reader.readline(1024 * 1024)

    def close(self):
        self.reader.close()
        self.socket.close()


def require(condition, message):
    if not condition:
        raise CheckError(message)


def command(args, **kwargs):
    return subprocess.run(args, capture_output=True, text=True, timeout=600, **kwargs)


def http(url, data=None, token=None, method=None, form=False, basic=None):
    headers = {}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if basic:
        encoded = ':'.join(urllib.parse.quote_plus(x) for x in basic)
        headers['Authorization'] = 'Basic ' + base64.b64encode(encoded.encode()).decode()
    if data is not None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
        data = (urllib.parse.urlencode(data) if form else json.dumps(data)).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            body = response.read(1024 * 1024)
            return response.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as error:
        try:
            body = json.loads(error.read(65536))
        except ValueError:
            body = {}
        return error.code, body


def wait_for(fn, seconds=180):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            value = fn()
            if value:
                return value
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(1)
    raise CheckError('fixture readiness timeout')


class Fixture:
    def __init__(self, provider, binary, root, evidence):
        self.provider, self.binary, self.root, self.evidence = provider, binary, root, evidence
        self.password = secrets.token_urlsafe(28)
        self.secret = secrets.token_urlsafe(32)
        self.bootstrap = secrets.token_hex(32)
        self.native = 'zc_' + secrets.token_urlsafe(32)
        self.results = []
        self.images = []
        self.token_shapes = {}
        self.daemon = None
        self.entries = []
        self.compose = root / 'compose.json'
        self.project = 'zc-oidc-' + secrets.token_hex(5)
        self.env = dict(os.environ, ZEROCLAW_CONFIG_DIR=str(root / 'config'),
                        ZEROCLAW_SOCKET=str(root / 'rpc.sock'), RUST_LOG='off')
        (root / 'config').mkdir()
        self.config = root / 'config' / 'config.toml'

    def docker(self, *args):
        return command(['docker', 'compose', '-p', self.project, '-f', str(self.compose), *args])

    def record(self, name, fn):
        started = time.monotonic()
        try:
            detail = fn()
            result = {'case': name, 'status': 'passed'}
            if detail:
                result['detail'] = detail
        except Exception as exc:
            # Never serialize arbitrary exception strings: browser/HTTP errors
            # can embed authorization URLs, callback codes or credentials.
            result = {'case': name, 'status': 'failed', 'error_type': type(exc).__name__}
            if isinstance(exc, CheckError):
                result['detail'] = str(exc)
            if name == 'real-provider-and-daemon-setup' and self.compose.exists():
                # Setup has not issued any OAuth tokens yet. Keep only error
                # diagnostics, redact fixture credentials and URLs, never env.
                logs = self.docker('logs', '--no-color', '--tail', '60')
                result['setup_errors'] = [self.scrub(line) for line in logs.stdout.splitlines()
                                          if re.search(r'error|exception|failed|fatal', line, re.I)][-12:]
        result['seconds'] = round(time.monotonic() - started, 2)
        self.results.append(result)
        print(json.dumps(result), flush=True)
        self.save()
        return result['status'] == 'passed'

    def save(self):
        self.evidence.mkdir(exist_ok=True)
        (self.evidence / f'{self.provider}.json').write_text(json.dumps({
            'provider': self.provider, 'source': os.environ.get('GITHUB_SHA'),
            'binary_sha256': hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            'images': self.images,
            'token_shapes': self.token_shapes,
            'binary_source': (self.binary.parent / 'source-sha.txt').read_text().strip(),
            'results': self.results,
        }, indent=2))

    def start(self):
        if self.provider == 'keycloak':
            self.setup_keycloak()
        else:
            self.setup_authentik()
        images = self.docker('images', '-q')
        require(images.returncode == 0, 'cannot record provider image identities')
        for image_id in sorted(set(images.stdout.split())):
            inspected = command(['docker', 'image', 'inspect', '--format', '{{json .RepoDigests}}', image_id])
            require(inspected.returncode == 0, 'cannot record provider image digest')
            self.images.append({'id': image_id, 'repo_digests': json.loads(inspected.stdout)})
        self.write_config()
        self.start_daemon()

    def setup_keycloak(self):
        def client(name, public):
            return {'clientId': name, 'enabled': True, 'protocol': 'openid-connect',
                    'publicClient': public, 'secret': self.secret,
                    'standardFlowEnabled': public, 'directAccessGrantsEnabled': False,
                    'serviceAccountsEnabled': not public,
                    'redirectUris': ['http://127.0.0.1/callback', 'http://127.0.0.1:*'],
                    'attributes': {'oauth2.device.authorization.grant.enabled': 'true',
                                   'access.token.header.type.rfc9068': 'true',
                                   'pkce.code.challenge.method': 'S256'},
                    'protocolMappers': [
                        {'name': 'client identity', 'protocol': 'openid-connect',
                         'protocolMapper': 'oidc-hardcoded-claim-mapper',
                         'config': {'claim.name': 'client_id', 'claim.value': name,
                                    'jsonType.label': 'String', 'access.token.claim': 'true',
                                    'introspection.token.claim': 'true'}},
                        {'name': 'audience', 'protocol': 'openid-connect',
                         'protocolMapper': 'oidc-audience-mapper',
                         'config': {'included.custom.audience': 'zeroclaw',
                                    'access.token.claim': 'true', 'introspection.token.claim': 'true'}},
                        {'name': 'reader role', 'protocol': 'openid-connect',
                         'protocolMapper': 'oidc-hardcoded-claim-mapper',
                         'config': {'claim.name': 'roles', 'claim.value': 'reader',
                                    'jsonType.label': 'String', 'access.token.claim': 'true',
                                    'introspection.token.claim': 'true'}}]}
        realm = {'realm': 'zc-test', 'enabled': True, 'sslRequired': 'none',
                 'accessTokenLifespan': 300, 'clients': [client('zc-human', True), client('zc-service', False)],
                 'users': [{'username': 'acceptance-user', 'enabled': True,
                            'emailVerified': True, 'firstName': 'Synthetic', 'lastName': 'User',
                            'email': 'acceptance@example.invalid',
                            'credentials': [{'type': 'password', 'value': self.password, 'temporary': False}]}]}
        (self.root / 'realm.json').write_text(json.dumps(realm))
        self.compose.write_text(json.dumps({'services': {'keycloak': {
            'image': 'quay.io/keycloak/keycloak:26.8.0',
            'command': ['start-dev', '--import-realm'],
            'ports': ['127.0.0.1:18080:8080'],
            'volumes': [str(self.root / 'realm.json') + ':/opt/keycloak/data/import/realm.json:ro'],
            'environment': {'KC_BOOTSTRAP_ADMIN_USERNAME': 'admin', 'KC_BOOTSTRAP_ADMIN_PASSWORD': self.bootstrap},
        }}}))
        require(self.docker('up', '-d').returncode == 0, 'keycloak startup failed')
        issuer = 'http://127.0.0.1:18080/realms/zc-test'
        wait_for(lambda: http(issuer + '/.well-known/openid-configuration')[0] == 200)
        self.entries = [dict(alias='human', issuer=issuer, audience='zeroclaw', client='zc-human'),
                        dict(alias='service', issuer=issuer, audience='zeroclaw', client='zc-service', secret=self.secret)]

    def setup_authentik(self):
        pg_secret = secrets.token_hex(24)
        salt = secrets.token_hex(12)
        password_hash = 'pbkdf2_sha256$1200000$' + salt + '$' + base64.b64encode(
            hashlib.pbkdf2_hmac('sha256', self.password.encode(), salt.encode(), 1200000)).decode()
        env = {'AUTHENTIK_POSTGRESQL__HOST': 'postgres', 'AUTHENTIK_POSTGRESQL__USER': 'authentik',
               'AUTHENTIK_POSTGRESQL__NAME': 'authentik', 'AUTHENTIK_POSTGRESQL__PASSWORD': pg_secret,
               'AUTHENTIK_SECRET_KEY': secrets.token_hex(48), 'AUTHENTIK_BOOTSTRAP_TOKEN': self.bootstrap,
               'AUTHENTIK_BOOTSTRAP_PASSWORD_HASH': password_hash.replace('$', '$$'),
               'AUTHENTIK_BOOTSTRAP_EMAIL': 'bootstrap@example.invalid', 'AUTHENTIK_ERROR_REPORTING__ENABLED': 'false'}
        image = 'ghcr.io/goauthentik/server:2026.8.3'
        self.compose.write_text(json.dumps({'services': {
            'postgres': {'image': 'postgres:16-alpine',
                         'environment': {'POSTGRES_DB': 'authentik', 'POSTGRES_USER': 'authentik', 'POSTGRES_PASSWORD': pg_secret},
                         'healthcheck': {'test': ['CMD-SHELL', 'pg_isready -U authentik'], 'interval': '5s', 'retries': 40},
                         'volumes': ['database:/var/lib/postgresql/data']},
            'server': {'image': image, 'command': 'server', 'environment': env,
                       'depends_on': {'postgres': {'condition': 'service_healthy'}},
                       'ports': ['127.0.0.1:19000:9000'], 'shm_size': '512mb'},
            'worker': {'image': image, 'command': 'worker', 'environment': env,
                       'depends_on': {'postgres': {'condition': 'service_healthy'}}}},
            'volumes': {'database': {}}}))
        require(self.docker('up', '-d').returncode == 0, 'authentik startup failed')
        base = 'http://127.0.0.1:19000/api/v3/'
        wait_for(lambda: http(base + 'flows/instances/', token=self.bootstrap)[0] == 200, 360)
        def api(path, data=None, method=None):
            status, body = http(base + path, data, self.bootstrap, method)
            require(status < 300, 'authentik API ' + path.split('?')[0] + ' status ' + str(status))
            return body
        flows = api('flows/instances/?page_size=100')['results']
        authorization = next(f['pk'] for f in flows if f['slug'] == 'default-provider-authorization-implicit-consent')
        invalidation = next(f['pk'] for f in flows if f['slug'] == 'default-provider-invalidation-flow')
        code_flow = api('flows/instances/', {'name': 'Acceptance device', 'title': 'Approve device',
                    'slug': 'acceptance-device', 'designation': 'stage_configuration', 'authentication': 'require_authenticated'})
        brand = api('core/brands/')['results'][0]
        api('core/brands/' + brand['brand_uuid'] + '/', {'flow_device_code': code_flow['pk']}, 'PATCH')
        keys = api('crypto/certificatekeypairs/?has_key=true')['results']
        require(bool(keys), 'authentik signing key absent')
        user = api('core/users/', {'username': 'acceptance-user', 'name': 'Synthetic User',
                                  'is_active': True, 'type': 'internal'})
        api('core/users/' + str(user['pk']) + '/set_password/', {'password': self.password})
        for alias in ['human', 'service']:
            client = 'zc-' + alias
            mapping = api('propertymappings/provider/scope/', {'name': 'Acceptance ' + alias,
                          'scope_name': 'openid', 'expression': 'return {"roles": ["reader"], "client_id": "' + client + '"}'})
            provider = api('providers/oauth2/', {'name': 'acceptance-' + alias,
                'authorization_flow': authorization, 'invalidation_flow': invalidation,
                'client_type': 'public' if alias == 'human' else 'confidential',
                'grant_types': ['authorization_code', 'urn:ietf:params:oauth:grant-type:device_code'] if alias == 'human' else ['client_credentials'],
                'client_id': client, 'client_secret': self.secret,
                'redirect_uris': [{'matching_mode': 'regex', 'url': r'^http://127\.0\.0\.1:[0-9]+/callback$'}],
                'property_mappings': [mapping['pk']], 'signing_key': keys[0]['pk'],
                'access_token_validity': 'minutes=5'})
            api('core/applications/', {'name': 'Acceptance ' + alias, 'slug': 'acceptance-' + alias, 'provider': provider['pk']})
            entry = dict(alias=alias, issuer='http://127.0.0.1:19000/application/o/acceptance-' + alias + '/',
                         audience=client, client=client)
            if alias == 'service':
                entry['secret'] = self.secret
            self.entries.append(entry)

    def write_config(self, validation='jwks', audience=None, cap=300, map_service=True):
        q = json.dumps
        text = '''schema_version = 3
[providers.models.ollama.default]
model = "acceptance-unused-model"
[risk_profiles.default]
[runtime_profiles.default]
[agents.default]
model_provider = "ollama.default"
risk_profile = "default"
runtime_profile = "default"
[permission_profiles.reader]
grants = { sessions = ["read"] }
[wss]
enabled = true
bind = "127.0.0.1"
port = 19781
[gateway]
host = "127.0.0.1"
port = 19617
require_pairing = true
paired_tokens = [''' + q(hashlib.sha256(self.native.encode()).hexdigest()) + ''']
'''
        for entry in self.entries:
            text += '\n[oidc.' + entry['alias'] + ']\n'
            for key, val in [('issuer', entry['issuer']), ('audience', audience or entry['audience']), ('client_id', entry['client']),
                             ('claim_path', 'roles'), ('validation', validation)]:
                text += key + ' = ' + q(val) + '\n'
            if 'secret' in entry:
                text += 'client_secret = ' + q(entry['secret']) + '\n'
            text += 'interactive_clients = ["zc-human"]\nservice_clients = ["zc-service"]\n'
            text += 'profile_map = { reader = "reader" }\n'
            text += 'service_profile_map = ' + ('{ "zc-service" = "reader" }' if map_service else '{}') + '\n'
            text += 'max_auth_lifetime_secs = ' + str(cap) + '\nrevalidation_secs = 5\n'
        self.config.write_text(text)
        self.config.chmod(0o600)

    def start_daemon(self):
        self.stop_daemon()
        saved = command([str(self.binary), 'config', 'set', 'security.trust_daemon_uid', 'true', '--no-interactive', '--json'], env=self.env)
        require(saved.returncode == 0, 'CLI config save failed')
        require((self.config.parent / '.secret_key').exists(), 'CLI config save did not provision signing key')
        self.daemon_log = open(self.root / 'daemon.log', 'w')
        self.daemon = subprocess.Popen([str(self.binary), 'daemon'], env=self.env,
                                        stdout=self.daemon_log, stderr=subprocess.STDOUT)
        def ready():
            require(self.daemon.poll() is None, 'daemon exited before readiness')
            with socket.create_connection(('127.0.0.1', 19781), timeout=1):
                return True
        wait_for(ready)
        cert = self.root / 'client-tls'
        if not cert.exists():
            result = command([str(self.binary), 'security', 'issue-client-cert', '--name', 'acceptance', '--out-dir', str(cert)], env=self.env)
            require(result.returncode == 0, 'client certificate issuance failed')
        self.tls = ssl.create_default_context(cafile=str(cert / 'ca.crt'))
        self.tls.load_cert_chain(str(cert / 'client.crt'), str(cert / 'client.key'))

    def stop_daemon(self):
        if self.daemon:
            self.daemon.terminate()
            try:
                self.daemon.wait(15)
            except subprocess.TimeoutExpired:
                self.daemon.kill()
                self.daemon.wait(5)
            self.daemon_log.close()
            self.daemon = None

    def rpc(self, token=None, provider=None):
        ws = connect('wss://127.0.0.1:19781', ssl=self.tls, open_timeout=10, proxy=None)
        params = {}
        if token is not None:
            params['auth_token'] = token
        if provider is not None:
            params['auth_provider'] = provider
        response = self.call(ws, 'initialize', params)
        return ws, response

    @staticmethod
    def call(ws, method, params=None):
        request_id = secrets.randbelow(1000000)
        ws.send(json.dumps({'jsonrpc': '2.0', 'id': request_id, 'method': method, 'params': params or {}}))
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            response = json.loads(ws.recv(timeout=max(0.01, deadline - time.monotonic())))
            if response.get('id') == request_id:
                return response
        raise CheckError('RPC response deadline exceeded')

    def accepted(self, token, alias):
        ws, response = self.rpc(token, 'oidc.' + alias)
        try:
            require('result' in response, 'OIDC initialize denied: ' + self.error_detail(response))
            require('result' in self.call(ws, 'session/list'), 'authorized read denied')
            denied = self.call(ws, 'config/set', {'prop': 'wss.port', 'value': 19782})
            require(denied.get('error', {}).get('code') == -32012, 'reader config write not forbidden')
        finally:
            ws.close()

    def denied(self, token=None, provider=None, code=-32010):
        ws, response = self.rpc(token, provider)
        try:
            require(response.get('error', {}).get('code') == code, 'unexpected initialize denial: ' + self.error_detail(response))
            require(self.call(ws, 'session/list').get('error', {}).get('code') == -32010,
                    'uninitialized connection did not return AUTH_REQUIRED')
        finally:
            ws.close()

    def enroll(self, alias, browser=None, device=False):
        args = [str(self.binary), 'oidc', 'login' if browser else 'token', alias]
        if browser and not device:
            args.append('--browser')
        if not browser:
            result = command(args, env=self.env)
            require(result.returncode == 0, 'CLI service enrollment failed')
            return self.check_token_output(result.stdout)
        proc = subprocess.Popen(args, env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        messages = queue.Queue()
        stderr_lines = []
        def drain():
            for line in proc.stderr:
                stderr_lines.append(line)
                messages.put(line)
        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        context = browser.new_context()
        page = context.new_page()
        try:
            deadline = time.monotonic() + 45
            url = None
            while time.monotonic() < deadline and url is None:
                try:
                    line = messages.get(timeout=1)
                except queue.Empty:
                    require(proc.poll() is None, 'interactive CLI exited before sign-in URL')
                    continue
                if 'Error:' in line:
                    raise CheckError('interactive CLI failed: ' + self.scrub(line.strip()))
                match = re.search(r'https?://[^\s\x1b]+', line)
                if match:
                    url = match.group().rstrip('.,')
            require(url is not None, 'CLI did not present sign-in URL')
            page.goto(url)
            deadline = time.monotonic() + 80
            while time.monotonic() < deadline and proc.poll() is None:
                # Playwright pierces authentik's open shadow roots.
                user = page.locator('input[name="username"], input[name="uidField"], input[autocomplete="username"]').first
                password = page.locator('input[type="password"]').first
                if user.is_visible():
                    user.fill('acceptance-user')
                if password.is_visible():
                    password.fill(self.password)
                button = page.locator('button[type="submit"], input[type="submit"]').first
                if button.is_visible():
                    button.click()
                else:
                    approve = page.get_by_role('button', name=re.compile(r'^(Continue|Confirm|Allow|Authorize|Yes|Submit|Approve|Log in|Sign in)$', re.I)).first
                    if approve.is_visible():
                        approve.click()
                page.wait_for_timeout(700)
            require(proc.poll() is not None, 'interactive browser flow timed out')
            reader.join(timeout=2)
            errors = [self.scrub(line.strip()) for line in stderr_lines if 'Error:' in line]
            require(proc.returncode == 0, 'CLI rejected completed browser flow: ' + '; '.join(errors))
            return self.check_token_output(proc.stdout.read())
        finally:
            context.close()
            if proc.poll() is None:
                proc.kill()
                proc.wait(5)

    @staticmethod
    def check_token_output(stdout):
        require(stdout.endswith('\n') and stdout.count('\n') == 1, 'CLI stdout is not exactly one token line')
        token = stdout.strip()
        require(bool(token) and not any(c.isspace() for c in token), 'CLI returned invalid token output')
        return token

    def scrub(self, text):
        for value in [self.password, self.secret, self.native, self.bootstrap]:
            text = text.replace(value, '[redacted]')
        text = re.sub(r'eyJ[A-Za-z0-9_\-.]+', '[jwt]', text)
        text = re.sub(r'https?://\S+', '[url]', text)
        return text[:500]

    def error_detail(self, response):
        error = response.get('error', {})
        return self.scrub(str(error.get('code')) + ': ' + str(error.get('message')))

    def run_cases(self, browser):
        tokens = {}
        def flow(name, alias, device=False):
            token = self.enroll(alias, browser if alias == 'human' else None, device)
            tokens[name] = token
            parts = token.split('.')
            if len(parts) == 3:
                header = json.loads(base64.urlsafe_b64decode(parts[0] + '==='))
                claims = json.loads(base64.urlsafe_b64decode(parts[1] + '==='))
                self.token_shapes[name] = {'typ': header.get('typ'), 'claim_names': sorted(claims)}
            self.accepted(token, alias)
        for name, alias, device in [('client-credentials', 'service', False), ('browser-pkce', 'human', False), ('device', 'human', True)]:
            self.record(name + '-cli-through-mtls-rpc', lambda n=name, a=alias, d=device: flow(n, a, d))
        self.record('mtls-without-bearer-denied', lambda: self.denied())
        self.record('bad-bearer-denied', lambda: self.denied('invalid-token', 'oidc.service'))
        self.record('native-token-wrong-provider-no-fallback', lambda: self.denied(self.native, 'oidc.service'))
        def native_control():
            ws, response = self.rpc(self.native, 'native')
            try:
                require('result' in response, 'native paired token rejected: ' + self.error_detail(response))
                require('result' in self.call(ws, 'session/list'), 'native read refused')
            finally:
                ws.close()
        self.record('native-pairing-positive-control', native_control)
        if 'client-credentials' in tokens:
            def fresh_control():
                self.write_config()
                self.start_daemon()
                service = self.enroll('service')
                self.accepted(service, 'service')
                return service
            def restored_control(service):
                self.write_config()
                self.start_daemon()
                self.accepted(service, 'service')
            def wrong_audience():
                service = fresh_control()
                self.write_config(audience='wrong-resource')
                self.start_daemon()
                self.denied(service, 'oidc.service')
                restored_control(service)
            self.record('wrong-audience-denied', wrong_audience)
            def unmapped():
                service = fresh_control()
                self.write_config(map_service=False)
                self.start_daemon()
                self.denied(service, 'oidc.service', code=-32012)
                restored_control(service)
            self.record('unmapped-service-denied', unmapped)
            def expiry():
                service = fresh_control()
                self.write_config(cap=1)
                self.start_daemon()
                time.sleep(2)
                self.denied(service, 'oidc.service')
                restored_control(service)
            self.record('offline-lifetime-cap-denied', expiry)
            def introspection():
                # Public enrollment entry uses JWKS; introspection needs a
                # configured confidential client's own secret.
                saved = self.entries
                self.entries = [e for e in saved if e['alias'] == 'service']
                try:
                    self.write_config(validation='introspection')
                    self.start_daemon()
                    fresh = self.enroll('service')
                    self.accepted(fresh, 'service')
                    entry = self.entries[0]
                    status, discovery = http(entry['issuer'].rstrip('/') + '/.well-known/openid-configuration')
                    require(status == 200 and discovery.get('revocation_endpoint'), 'revocation endpoint absent')
                    ws, initialized = self.rpc(fresh, 'oidc.service')
                    try:
                        require('result' in initialized, 'introspection initialize failed')
                        require('result' in self.call(ws, 'session/list'), 'introspection read failed')
                        status, _ = http(discovery['revocation_endpoint'], {'token': fresh, 'token_type_hint': 'access_token'},
                                         form=True, basic=(entry['client'], entry['secret']))
                        require(status == 200, 'provider revocation failed')
                        # RPC identities intentionally retain no raw token. They
                        # fail closed at the revalidation deadline and require
                        # a fresh handshake; they do not poll introspection.
                        time.sleep(6)
                        expired = self.call(ws, 'session/list')
                        require(expired.get('error', {}).get('code') == -32010,
                                'existing connection outlived introspection deadline')
                    finally:
                        ws.close()
                    self.denied(fresh, 'oidc.service')
                finally:
                    self.entries = saved
            self.record('introspection-deadline-and-revoked-reconnect', introspection)
        self.write_config()
        self.start_daemon()
        self.record('rest-unauthenticated-denied', lambda: require(http('http://127.0.0.1:19617/api/sessions')[0] == 401,
                                                                  'unauthenticated REST sessions accepted'))
        self.record('native-control-after-rollback', native_control)
        def local_recovery():
            local = LocalConnection(self.root / 'rpc.sock')
            try:
                require('result' in self.call(local, 'initialize'), 'trusted daemon UID refused')
                require('result' in self.call(local, 'config/set', {'prop': 'gateway.paired_tokens', 'value': []}),
                        'local pairing revocation failed')
                self.denied(self.native, 'native')
                restored = self.call(local, 'config/set', {'prop': 'gateway.paired_tokens',
                                                         'value': [hashlib.sha256(self.native.encode()).hexdigest()]})
                require('result' in restored, 'local recovery refused')
                native_control()
                self.denied()
            finally:
                local.close()
        self.record('local-uid-recovery-after-remote-lockout', local_recovery)
        def config_rollback():
            entries = self.entries
            try:
                self.entries = []
                self.write_config()
                self.start_daemon()
                native_control()
                self.denied()
                if 'client-credentials' in tokens:
                    self.denied(tokens['client-credentials'], 'oidc.service')
            finally:
                self.entries = entries
            self.write_config()
            self.start_daemon()
            native_control()
            if 'client-credentials' in tokens:
                self.accepted(self.enroll('service'), 'service')
        self.record('oidc-config-removal-and-restore-keeps-remote-closed', config_rollback)

    def close(self):
        self.stop_daemon()
        if self.compose.exists():
            result = self.docker('down', '--volumes', '--remove-orphans')
            self.results.append({'case': 'disposable-container-cleanup', 'status': 'passed' if result.returncode == 0 else 'failed'})
        self.save()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('provider', choices=['keycloak', 'authentik'])
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    evidence = Path('provider-evidence').resolve()
    with tempfile.TemporaryDirectory(prefix='zc-oidc-') as directory:
        fixture = Fixture(args.provider, args.binary.resolve(), Path(directory), evidence)
        try:
            if fixture.record('real-provider-and-daemon-setup', fixture.start):
                with sync_playwright() as playwright:
                    browser = playwright.chromium.launch()
                    try:
                        fixture.run_cases(browser)
                    finally:
                        browser.close()
        finally:
            fixture.close()
    raise SystemExit(any(row['status'] == 'failed' for row in fixture.results))


if __name__ == '__main__':
    main()
