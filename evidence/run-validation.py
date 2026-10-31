"""Run only in the disposable Linux validation checkout, after budget approval."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

PACKAGE = Path(__file__).resolve().parent
SOURCE = Path(sys.argv[1]).resolve()
MANIFEST = json.loads((PACKAGE / 'source-manifest.json').read_text())
RESULTS = PACKAGE / 'results'
RESULTS.mkdir(exist_ok=True)
os.environ.update(CARGO_BUILD_JOBS='2', CARGO_INCREMENTAL='0',
                  CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0',
                  CARGO_TERM_COLOR='never', CARGO_TARGET_DIR=str(SOURCE / 'target'))
receipts = []

def sha(data):
    return hashlib.sha256(data).hexdigest()

def run(name, args, expected=0):
    print(f'RUN {name}: {args}', flush=True)
    started = time.monotonic()
    with (RESULTS / f'{name}.log').open('w') as out:
        result = subprocess.run(args, cwd=SOURCE, stdout=out, stderr=subprocess.STDOUT,
                                text=True, timeout=3000)
    log = (RESULTS / f'{name}.log').read_text(errors='replace')
    print(log[-16000:], flush=True)
    receipts.append(dict(name=name, args=args, exit=result.returncode,
                         seconds=round(time.monotonic()-started, 2)))
    (RESULTS / 'commands.json').write_text(json.dumps(receipts, indent=2)+'\n')
    assert result.returncode == expected, f'{name}: unexpected exit {result.returncode}'
    return log

def verify_source():
    for path, expected in MANIFEST['files'].items():
        assert sha((SOURCE/path).read_bytes()) == expected, f'source changed: {path}'

def test(name, selector, expected=0):
    text = run(name, ['cargo', 'test', '--locked', '-p', 'zeroclaw-gateway', '--lib',
                      selector, '--', '--nocapture'], expected)
    assert re.search(r'running [1-9][0-9]* tests?', text), 'no selected tests ran'
    return text

head = subprocess.check_output(['git','rev-parse','HEAD'], cwd=SOURCE, text=True).strip()
assert head == MANIFEST['base'], 'wrong base'
assert not subprocess.check_output(['git','status','--porcelain'], cwd=SOURCE), 'dirty checkout'
assert sha((PACKAGE/'repair.patch').read_bytes()) == MANIFEST['patch_sha256']
run('apply-check', ['git','apply','--check',str(PACKAGE/'repair.patch')])
run('apply', ['git','apply',str(PACKAGE/'repair.patch')])
verify_source()
run('toolchain', ['rustc','--version','--verbose'])
run('format', ['cargo','fmt','--all','--','--check'])
run('whitespace', ['git','diff','--check'])
test('oidc-positive', 'api_oidc::tests::')
run('clippy', ['cargo','clippy','--locked','-p','zeroclaw-gateway','--all-targets',
               '--no-deps','--','-D','warnings'])
api = SOURCE/'crates/zeroclaw-gateway/src/api_oidc.rs'
original = api.read_bytes()
marker = b'if browser_matches(&headers, &pending) {'
assert original.count(marker) == 1
try:
    api.write_bytes(original.replace(marker, b'if true {'))
    negative = test('binding-negative-control',
                    'api_oidc::tests::enrollment_binding_refuses_other_browsers_before_exchange_and_consumes_the_flow', 101)
    assert 'enrollment_binding_refuses_other_browsers_before_exchange_and_consumes_the_flow ... FAILED' in negative
    assert re.search(r'left:\s*200\s+right:\s*400', negative), 'failure did not prove guard removal'
finally:
    api.write_bytes(original)
    verify_source()
    (RESULTS/'negative-restoration.json').write_text(json.dumps(MANIFEST, indent=2)+'\n')
verify_source()
test('oidc-restored', 'api_oidc::tests::')

# Temporary native HTTP fixture only. It uses the production enrollment routes,
# prefix and response headers. It is not a complete production daemon or live IdP.
fixture = (PACKAGE/'browser-fixture.rs').read_bytes()
assert original.rstrip().endswith(b'}')
ready = PACKAGE/'browser-ready.txt'
if ready.exists():
    raise RuntimeError('stale browser fixture output')
os.environ['ZC_BINDING_QA_READY'] = str(ready)
process = None
try:
    api.write_bytes(original.rstrip()[:-1]+b'\n'+fixture+b'\n}\n')
    with (RESULTS/'browser-server.log').open('w') as out:
        process = subprocess.Popen(['cargo','test','--locked','-p','zeroclaw-gateway','--lib',
            'api_oidc::tests::browser_binding_acceptance_harness','--','--ignored','--exact','--nocapture'],
            cwd=SOURCE, stdout=out, stderr=subprocess.STDOUT)
        deadline = time.monotonic()+900
        while not ready.exists():
            assert process.poll() is None, 'fixture exited before binding its listener'
            assert time.monotonic()<deadline, 'fixture startup deadline'
            time.sleep(1)
        run('browser', ['node', str(PACKAGE/'browser-check.mjs')])
        assert process.wait(timeout=30) == 0, 'fixture failed'
    browser_log = (RESULTS/'browser-server.log').read_text(errors='replace')
    assert '1 passed; 0 failed' in browser_log, 'fixture was not executed'
finally:
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
    api.write_bytes(original)
    verify_source()
    (RESULTS/'browser-restoration.json').write_text(json.dumps(MANIFEST, indent=2)+'\n')
verify_source()
test('oidc-final', 'api_oidc::tests::')
run('final-whitespace', ['git','diff','--check'])
(RESULTS/'validated-source.json').write_text(json.dumps(MANIFEST, indent=2)+'\n')
print('VALIDATION_COMPLETE: exact source restored; all required package stages passed', flush=True)
