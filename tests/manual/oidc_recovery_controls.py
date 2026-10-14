"""Require real regression failures on old code and deliberately broken guards."""
import json
from pathlib import Path
import re
import subprocess

BASELINE = 'a7d92f90854181b2a1b30cc2cab20aaf16d61020'
FILES = ['crates/zeroclaw-runtime/src/rpc/dispatch.rs', 'crates/zeroclaw-runtime/src/rpc/session.rs']
ROOT = Path('regression-evidence')
ROOT.mkdir(exist_ok=True)
SOURCE = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
original = {name: Path(name).read_bytes() for name in FILES}


def rejected(label, test):
    name = 'rpc::dispatch::tests::' + test
    result = subprocess.run(['cargo', 'test', '--locked', '-p', 'zeroclaw-runtime', '--lib', name, '--', '--exact'], capture_output=True, text=True)
    output = result.stdout + result.stderr
    (ROOT / (label + '.log')).write_text(output)
    summaries = re.findall(r'^test result:.*$', output, re.M)
    verified = (
        result.returncode == 101
        and re.findall(r'^running \d+ tests?$', output, re.M) == ['running 1 test']
        and re.findall(r'^test \S+ \.\.\. .+$', output, re.M) == [f'test {name} ... FAILED']
        and len(summaries) == 1
        and summaries[0].startswith('test result: FAILED. 0 passed; 1 failed; 0 ignored;')
    )
    record = {'source': SOURCE, 'test': name, 'exit': result.returncode, 'expected_failure_verified': verified}
    (ROOT / (label + '.json')).write_text(json.dumps(record, indent=2))
    print(json.dumps({'control': label, **record}), flush=True)
    if not verified:
        print(output[-12000:])
        raise SystemExit('negative control did not execute and fail exactly once')


try:
    for name in FILES:
        Path(name).write_bytes(subprocess.check_output(['git', 'show', BASELINE + ':' + name]))
    rejected('recovery-old-code', 'remote_chat_restore_reopens_owned_nonempty_history')
finally:
    for name, contents in original.items():
        Path(name).write_bytes(contents)

for mutation in ['durable-owner', 'current-authority']:
    try:
        source = original[FILES[0]].decode()
        start = source.index('    async fn publish_remote_chat_restore(')
        end = source.index('    async fn ensure_session_incarnation(', start)
        method = source[start:end]
        if mutation == 'durable-owner':
            before = 'if actual.is_none() || actual != candidate.owner_principal_id.as_deref()'
            assert method.count(before) == 1
            method = method.replace(before, 'if false')
        else:
            a = method.index('let _authority = self')
            b = method.index('publish(candidate);', a)
            method = method[:a] + method[b:]
        Path(FILES[0]).write_text(source[:start] + method + source[end:])
        rejected('recovery-mutant-' + mutation, 'remote_chat_restore_rechecks_admission_and_publication')
    finally:
        for name, contents in original.items():
            Path(name).write_bytes(contents)

assert all(Path(name).read_bytes() == contents for name, contents in original.items())
print('Recovery controls restored the exact source bytes.', flush=True)
