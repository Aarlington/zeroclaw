"""Fail-closed case inventory for disposable provider receipts; standard library only."""
from collections import Counter
import re

COMMON_CASES = (
    'real-provider-and-daemon-setup',
    'client-credentials-cli-through-mtls-rpc',
    'browser-pkce-cli-through-mtls-rpc',
    'device-cli-through-mtls-rpc',
    'mtls-without-bearer-denied',
    'bad-bearer-denied',
    'native-token-wrong-provider-no-fallback',
    'native-pairing-positive-control',
    'signed-reconnect-and-stale-continuity-refusal',
    'wrong-audience-denied',
    'unmapped-service-denied',
    'offline-lifetime-cap-denied',
    'introspection-deadline-and-revoked-reconnect',
    'rest-unauthenticated-denied',
    'native-control-after-rollback',
    'local-uid-recovery-after-remote-lockout',
    'oidc-config-removal-and-restore-keeps-remote-closed',
    'legacy-nevis-retirement-and-protected-config-restore',
    'disposable-container-cleanup',
)
KEYCLOAK_CASES = (
    'two-real-principals-isolation-and-live-revocation',
    'reserved-client-id-oauth-basic-cli',
    'populated-principal-storage-survives-daemon-restart',
    'provider-expiry-established-connection-and-reenrollment',
)


def expected_cases(provider):
    if provider not in ('keycloak', 'authentik'):
        raise ValueError('unknown acceptance provider')
    return COMMON_CASES + (KEYCLOAK_CASES if provider == 'keycloak' else ())


def evaluate(provider, results, *, complete):
    expected = set(expected_cases(provider))
    counts = Counter(row.get('case') for row in results)
    missing = sorted(expected - counts.keys())
    unexpected = sorted(str(name) for name in counts.keys() - expected)
    duplicate = sorted(str(name) for name, count in counts.items() if count != 1)
    nonpassing = sorted(str(row.get('case')) for row in results if row.get('status') != 'passed')
    passed = complete is True and not (missing or unexpected or duplicate or nonpassing)
    return {'passed': bool(passed), 'complete': bool(complete),
            'expected_count': len(expected), 'observed_count': len(results),
            'missing': missing, 'unexpected': unexpected, 'duplicate': duplicate,
            'nonpassing': nonpassing}


def exact_cargo_pass(name, exit_code, output):
    """Cargo success alone also covers zero selections and ignored tests."""
    lines = output.splitlines()
    runs = [line for line in lines if re.fullmatch(r'running \d+ tests?', line)]
    records = [line for line in lines if re.match(r'^test \S+ \.\.\. ', line)]
    summaries = [line for line in lines if line.startswith('test result:')]
    return (exit_code == 0 and runs == ['running 1 test']
            and records == [f'test {name} ... ok'] and len(summaries) == 1
            and re.match(r'^test result: ok\. 1 passed; 0 failed; 0 ignored;', summaries[0]) is not None)
