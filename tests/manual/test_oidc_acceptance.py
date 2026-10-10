"""Adversarial tests of evidence and failure paths, without provider dependencies."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from oidc_acceptance_contract import evaluate, exact_cargo_pass, expected_cases
from oidc_real_providers import CheckError, Fixture


class ReceiptTests(unittest.TestCase):
    def receipts(self, provider='keycloak'):
        return [{'case': name, 'status': 'passed'} for name in expected_cases(provider)]

    def test_complete_provider_matrices_pass(self):
        for provider, count in [('keycloak', 22), ('authentik', 18)]:
            with self.subTest(provider=provider):
                result = evaluate(provider, self.receipts(provider), complete=True)
                self.assertEqual(result['expected_count'], count)
                self.assertTrue(result['passed'])

    def test_each_missing_case_fails_even_when_all_remaining_cases_pass(self):
        for provider in ['keycloak', 'authentik']:
            rows = self.receipts(provider)
            for index, row in enumerate(rows):
                with self.subTest(provider=provider, omitted=row['case']):
                    result = evaluate(provider, rows[:index] + rows[index + 1:], complete=True)
                    self.assertFalse(result['passed'])
                    self.assertEqual(result['missing'], [row['case']])

    def test_duplicate_success_cannot_replace_missing_case(self):
        rows = self.receipts()
        rows[-1] = rows[0].copy()
        self.assertFalse(evaluate('keycloak', rows, complete=True)['passed'])

    def test_unknown_case_and_unknown_status_fail(self):
        for mutation in [('case', 'unreviewed-case'), ('status', 'skipped'), ('status', 'failed')]:
            with self.subTest(mutation=mutation):
                rows = self.receipts()
                rows[0][mutation[0]] = mutation[1]
                self.assertFalse(evaluate('keycloak', rows, complete=True)['passed'])

    def test_interrupted_run_cannot_pass_with_successful_rows(self):
        self.assertFalse(evaluate('keycloak', self.receipts(), complete=False)['passed'])

    def test_authentik_cannot_inherit_keycloak_success(self):
        self.assertFalse(evaluate('authentik', self.receipts(), complete=True)['passed'])


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.binary = root / 'zeroclaw'
        self.binary.write_bytes(b'synthetic-binary')
        (root / 'source-sha.txt').write_text('a' * 40)
        (root / 'production-source-sha.txt').write_text('b' * 40)
        self.fixture = Fixture('keycloak', self.binary, root, root / 'evidence')

    def test_restart_is_detected_even_when_pid_is_reused(self):
        old = {'pid': 10, 'start_ticks': 20, 'starts': 1}
        for changed in [{'pid': 10, 'start_ticks': 21, 'starts': 1},
                        {'pid': 10, 'start_ticks': 20, 'starts': 2}]:
            with self.subTest(changed=changed), patch.object(self.fixture, 'daemon_identity', return_value=changed):
                with self.assertRaises(CheckError):
                    self.fixture.same_daemon(old)

    def test_dead_daemon_cannot_supply_continuity_evidence(self):
        self.fixture.daemon = Mock(pid=10)
        self.fixture.daemon.poll.return_value = 1
        with self.assertRaises(CheckError):
            self.fixture.daemon_identity()

    def test_handshake_exception_closes_connection(self):
        ws = Mock()
        module = types.ModuleType('websockets.sync.client')
        module.connect = Mock(return_value=ws)
        self.fixture.tls = object()
        with patch.dict(sys.modules, {'websockets.sync.client': module}), \
             patch.object(self.fixture, 'call', side_effect=TimeoutError('opaque-secret')):
            with self.assertRaises(TimeoutError):
                self.fixture.rpc()
        ws.close.assert_called_once_with()

    def test_peer_error_message_cannot_leak_opaque_credentials(self):
        detail = self.fixture.error_detail({'error': {'code': -32010, 'message': 'opaque-secret'}})
        self.assertEqual(detail, 'RPC code -32010')
        self.assertNotIn('opaque-secret', detail)

    def test_failed_setup_does_not_publish_provider_logs(self):
        self.fixture.compose.write_text('{}')
        self.fixture.docker = Mock(return_value=types.SimpleNamespace(stdout='fatal password=opaque-secret'))
        with contextlib.redirect_stdout(io.StringIO()):
            self.fixture.record('real-provider-and-daemon-setup', Mock(side_effect=RuntimeError('opaque-secret')))
        output = (self.fixture.evidence / 'keycloak.json').read_text()
        self.assertNotIn('opaque-secret', output)
        self.assertFalse(json.loads(output)['acceptance']['passed'])

    def test_cleanup_failure_remains_failure_in_final_receipt(self):
        self.fixture.results = [{'case': name, 'status': 'passed'} for name in expected_cases('keycloak')
                                if name != 'disposable-container-cleanup']
        self.fixture.compose.write_text('{}')
        self.fixture.docker = Mock(return_value=types.SimpleNamespace(returncode=1))
        self.fixture.close()
        receipt = json.loads((self.fixture.evidence / 'keycloak.json').read_text())
        self.assertTrue(receipt['acceptance']['complete'])
        self.assertFalse(receipt['acceptance']['passed'])
        self.assertIn('disposable-container-cleanup', receipt['acceptance']['nonpassing'])


class CargoReceiptTests(unittest.TestCase):
    output = 'running 1 test\ntest module::case ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 100 filtered out; finished in 0.1s\n'

    def test_exact_named_success_passes(self):
        self.assertTrue(exact_cargo_pass('module::case', 0, self.output))

    def test_nonzero_exit_overrides_success_text(self):
        self.assertFalse(exact_cargo_pass('module::case', 101, self.output))

    def test_duplicate_test_or_summary_cannot_pass(self):
        for extra in ['test module::case ... ok\n', 'running 1 test\n', self.output.splitlines()[-1] + '\n']:
            with self.subTest(extra=extra):
                self.assertFalse(exact_cargo_pass('module::case', 0, self.output + extra))

    def test_zero_ignored_or_wrong_selection_cannot_pass(self):
        for output in [self.output.replace('running 1 test', 'running 0 tests'),
                       self.output.replace('0 ignored', '1 ignored'),
                       self.output.replace('module::case', 'module::other')]:
            with self.subTest(output=output):
                self.assertFalse(exact_cargo_pass('module::case', 0, output))


if __name__ == '__main__':
    unittest.main()
