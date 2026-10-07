#!/usr/bin/env python3
"""Require exact execution of current-head regressions; baseline proof is separate."""
import json
from pathlib import Path
import subprocess

TESTS = [
    'security::auth_provider::enrollment::tests::enrollment_basic_credentials_round_trip_on_every_endpoint',
    'rpc::tui_identity::tests::config_signing_key_is_used_when_runtime_data_lives_elsewhere',
    'rpc::dispatch::tests::scoped_principals_sessions_are_isolated',
    'rpc::dispatch::tests::session_configure_revoked_at_commit_changes_neither_overrides_nor_agent',
    'tools::delegate::tests::factory_delegate_inherits_private_memory_owner_before_any_action',
]
evidence = Path('regression-evidence')
evidence.mkdir(exist_ok=True)
source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
for index, name in enumerate(TESTS):
    result = subprocess.run(['cargo', 'test', '--locked', '-p', 'zeroclaw-runtime', '--lib', name, '--', '--exact'],
                            capture_output=True, text=True)
    output = result.stdout + result.stderr
    (evidence / f'current-{index}.log').write_text(output)
    verified = (result.returncode == 0 and 'running 1 test' in output
                and f'test {name} ... ok' in output and 'test result: ok. 1 passed; 0 failed;' in output)
    record = {'source': source, 'test': name, 'exit': result.returncode,
              'exact_pass_verified': verified}
    (evidence / f'current-{index}.json').write_text(json.dumps(record, indent=2))
    print(json.dumps(record), flush=True)
    if not verified:
        print(output[-12000:])
        raise SystemExit('named regression did not execute and pass exactly once')
