"""Fork-only exact tests and required negative controls for the SOP permission fix."""
import json
from pathlib import Path
import re
import subprocess

PRODUCTION = '0494b14bd9a25471ae5c2d0c27ee224554a59524'
BASELINE = 'c2ad7a8e62d22accbe13387927b8f6869ed46baa'
WORKSHOP = Path('crates/zeroclaw-runtime/src/tools/sop_workshop.rs')
ALIAS = Path('crates/zeroclaw-runtime/src/tools/skill_tool.rs')
EVIDENCE = Path('regression-evidence')
EVIDENCE.mkdir(exist_ok=True)
SOURCE = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
TESTS = [
    'rpc::dispatch::tests::principal_sop_workshop_refuses_direct_and_alias_effects',
    'rpc::dispatch::tests::principal_sop_workshop_queued_demotion_prevents_persistence',
    'tools::delegate::tests::withheld_session_tools_do_not_reach_delegate_children',
    'tools::sop_workshop::tests::propose_and_list_round_trip',
    'tools::sop_workshop::tests::apply_resolves_shared_sops_under_install_root_and_preserves_existing',
    'tools::tests::sop_workshop_registered_only_when_procedural_memory_enabled',
    'agent::agent::tests::withholding_session_data_tools_removes_aliases_and_nested_executors',
    'tools::delegate::tests::withheld_session_tools_do_not_reach_independent_targets',
    'tools::delegate::tests::withheld_session_tools_do_not_reach_an_independent_grandchild',
    'rpc::dispatch::tests::principal_native_history_uses_final_admission_and_monotonic_withholding',
    'rpc::dispatch::tests::demoted_principal_loses_session_data_tools_at_its_next_prompt',
    'session_sqlite::tests::with_session_owner_blocks_other_connections_until_effect_finishes',
    'rpc::session::tests::session_mode_replacement_rejects_owner_change_without_generation_change',
    'rpc::session::tests::session_mode_replacement_publication_is_capacity_neutral_and_fenced',
    'rpc::dispatch::tests::remote_chat_restore_trim_rechecks_owner_and_authority_before_writing',
    'rpc::dispatch::tests::session_new_persists_a_restore_time_trim_before_going_live_for_chat_mode',
    'rpc::dispatch::tests::remote_chat_restore_administrator_still_needs_durable_ownership',
    'rpc::dispatch::tests::remote_chat_restore_reopens_owned_nonempty_history',
    'rpc::dispatch::tests::remote_chat_restore_refuses_unproven_or_ambiguous_ownership',
    'rpc::dispatch::tests::remote_chat_restore_cannot_take_another_live_tui_binding',
    'rpc::dispatch::tests::remote_chat_restore_rechecks_admission_and_publication',
    'rpc::dispatch::tests::remote_resume_admission_wait_uses_current_principal',
    'rpc::dispatch::tests::fast_remote_resume_rejects_owner_changed_after_authorization',
    'rpc::dispatch::tests::remote_cross_mode_resume_preserves_a_rehydrated_successor',
    'rpc::dispatch::tests::forwarded_environment_remote_resume_and_prompt_are_refused_without_mutation',
    'rpc::dispatch::tests::remote_resume_rechecks_channels_at_final_agent_install',
    'security::auth_provider::enrollment::tests::enrollment_basic_credentials_round_trip_on_every_endpoint',
    'rpc::tui_identity::tests::config_signing_key_is_used_when_runtime_data_lives_elsewhere',
    'rpc::dispatch::tests::scoped_principals_sessions_are_isolated',
    'rpc::dispatch::tests::session_configure_revoked_at_commit_changes_neither_overrides_nor_agent',
    'tools::delegate::tests::factory_delegate_inherits_private_memory_owner_before_any_action',
    'rpc::dispatch::tests::cron_patch_rechecks_authority_and_row_after_sqlite_writer_wait',
    'rpc::dispatch::tests::sop_run_and_decide_are_refused_after_admin_demotion',
]


def run(label, test, failure=None):
    package = 'zeroclaw-infra' if test.startswith('session_sqlite::') else 'zeroclaw-runtime'
    result = subprocess.run(
        ['cargo', 'test', '--locked', '-p', package, '--lib', test, '--', '--exact'],
        capture_output=True, text=True, timeout=1800,
    )
    output = result.stdout + result.stderr
    (EVIDENCE / (label + '.log')).write_text(output)
    expected = 'FAILED' if failure else 'ok'
    prefix = ('test result: FAILED. 0 passed; 1 failed; 0 ignored;' if failure
              else 'test result: ok. 1 passed; 0 failed; 0 ignored;')
    summaries = re.findall(r'^test result:.*$', output, re.M)
    verified = (
        result.returncode == (101 if failure else 0)
        and re.findall(r'^running \d+ tests?$', output, re.M) == ['running 1 test']
        and re.findall(r'^test \S+ \.\.\. .+$', output, re.M) == [f'test {test} ... {expected}']
        and len(summaries) == 1 and summaries[0].startswith(prefix)
        and (failure is None or failure in output)
    )
    record = dict(source=SOURCE, production=PRODUCTION, label=label, test=test,
                  exit=result.returncode, expected_failure=failure, verified=verified)
    (EVIDENCE / (label + '.json')).write_text(json.dumps(record, indent=2))
    print(json.dumps(record), flush=True)
    if not verified:
        print(output[-18000:], flush=True)
        raise SystemExit('exact regression contract failed: ' + label)


original = {path: path.read_bytes() for path in [WORKSHOP, ALIAS]}
try:
    WORKSHOP.write_bytes(subprocess.check_output(['git', 'show', BASELINE + ':' + WORKSHOP.as_posix()]))
    for index, marker in enumerate([
        'non-admin workshop effect escaped through sop_workshop',
        'queued demotion must withhold sop_workshop',
        'the sync child was offered sop_workshop',
    ]):
        run('old-code-' + str(index), TESTS[index], marker)
finally:
    for path, data in original.items():
        path.write_bytes(data)

try:
    source = original[ALIAS].decode()
    guard = 'self.target_tool.requires_unrestricted_principal()'
    assert source.count(guard) == 1
    ALIAS.write_text(source.replace(guard, 'false'))
    run('alias-guard-mutant', TESTS[0], 'non-admin workshop effect escaped through workshop__apply')
finally:
    for path, data in original.items():
        path.write_bytes(data)

assert all(path.read_bytes() == data for path, data in original.items())
subprocess.run(['git', 'diff', '--exit-code'], check=True)
for index, test in enumerate(TESTS):
    run('current-' + str(index), test)
print('Exact source restored; all required controls and current regressions verified.', flush=True)
