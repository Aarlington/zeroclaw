#!/usr/bin/env python3
"""Transplant only the new HTTP regression onto the known baseline enrollment."""
import json
from pathlib import Path
import subprocess

source = Path('crates/zeroclaw-runtime/src/security/auth_provider/enrollment.rs')
base = 'cb2e697b0faaaa5d319440259413f13874378111'
name = 'security::auth_provider::enrollment::tests::enrollment_basic_credentials_round_trip_on_every_endpoint'
fixed = source.read_text()
start = fixed.index('    #[tokio::test]\n    async fn enrollment_basic_credentials_round_trip_on_every_endpoint()')
end = fixed.index('    #[tokio::test]', start + 10)
test = fixed[start:end]
baseline = subprocess.check_output(['git', 'show', f'{base}:{source.as_posix()}'], text=True)
marker = '    #[tokio::test]\n    async fn token_responses_are_validated_before_success_is_advertised()'
assert baseline.count(marker) == 1
evidence = Path('regression-evidence')
evidence.mkdir(exist_ok=True)
try:
    source.write_text(baseline.replace(marker, test + marker))
    result = subprocess.run(['cargo', 'test', '--locked', '-p', 'zeroclaw-runtime', '--lib', name, '--', '--exact'],
                            capture_output=True, text=True)
    output = result.stdout + result.stderr
    (evidence / 'enrollment-baseline.log').write_text(output)
    verified = (result.returncode == 101 and 'running 1 test' in output
                and f'test {name} ... FAILED' in output
                and 'literal credential separator reached the wire' in output)
    record = {'base': base, 'test': name, 'exit': result.returncode, 'expected_failure_verified': verified}
    (evidence / 'enrollment-baseline.json').write_text(json.dumps(record, indent=2))
    print(json.dumps(record), flush=True)
    if not verified:
        print(output[-12000:])
        raise SystemExit('baseline did not demonstrate the specific regression')
finally:
    source.write_text(fixed)
