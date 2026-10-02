"""Run the new regressions against the original combined source, then restore it.

Only test functions and the two inert SOP test pause calls are transplanted.
Compilation errors, missing tests, or unexpected passes fail this proof run.
Run in a disposable checkout; no credential or deployment configuration is used.
"""

import json
from pathlib import Path
import subprocess

BASE = "6ad797b46372feee2b1a772ecf4c4cfada2cd0f6"
ROOT = Path(__file__).resolve().parents[2]
PREFIX = "crates/zeroclaw-runtime/src/"
CASES = [
    ("tools/delegate.rs", "#[tokio::test]", "async fn",
     "factory_delegate_inherits_private_memory_owner_before_any_action",
     "owned_background_delegate_refuses_before_creating_shared_results",
     "tools::delegate::tests"),
    ("rpc/dispatch.rs", "#[tokio::test]", "async fn",
     "sop_decide_rechecks_before_lookup_and_final_projection",
     "sop_run_and_decide_are_refused_after_admin_demotion", "rpc::dispatch::tests"),
    ("rpc/dispatch.rs", "#[tokio::test]", "async fn",
     "session_configure_revoked_at_commit_changes_neither_overrides_nor_agent",
     "session_configure_stale_gen_replaced_during_provider_build", "rpc::dispatch::tests"),
    ("live_config_authority.rs", "#[test]", "fn",
     "selection_capture_finishes_while_a_writer_waits_for_an_effect_read",
     "cloned_authority_preserves_config_and_write_lock_identity", "live_config_authority::tests"),
]
paths = {PREFIX + item[0] for item in CASES} | {PREFIX + "rpc/session.rs", PREFIX + "tools/mod.rs"}
original = {path: (ROOT / path).read_bytes() for path in paths}
baseline = {
    path: subprocess.check_output(["git", "show", f"{BASE}:{path}"], cwd=ROOT).decode()
    for path in paths
}
evidence = ROOT / "acceptance-evidence"
evidence.mkdir(exist_ok=True)
results = []
try:
    for filename, attribute, kind, name, successor, _ in CASES:
        path = PREFIX + filename
        current = original[path].decode().replace("\r\n", "\n")
        begin = f"    {attribute}\n    {kind} {name}("
        end = f"    {attribute}\n    {kind} {successor}("
        start = current.index(begin)
        test = current[start:current.index(end, start)]
        assert baseline[path].count(end) == 1
        baseline[path] = baseline[path].replace(end, test + end)
    path = PREFIX + "rpc/dispatch.rs"
    start = baseline[path].index("    async fn handle_sops_decide(")
    end = baseline[path].index("    fn handle_sops_validate(", start)
    handler = baseline[path][start:end]
    handler = handler.replace(
        "        let mut resolved_outcome = None;",
        '        let mut resolved_outcome = None;\n'
        '        self.ctx.sessions.wait_test_effect_pause("sop-decision-admission").await;',
    )
    needle = "        let overlay = crate::sop::run_overlay_for(&sop, &engine, &req.run_id)"
    assert handler.count(needle) == 1
    handler = handler.replace(needle,
        '        self.ctx.sessions.wait_test_effect_pause("sop-decision-result").await;\n' + needle)
    baseline[path] = baseline[path][:start] + handler + baseline[path][end:]
    for path, content in baseline.items():
        (ROOT / path).write_text(content, encoding="utf-8", newline="\n")
    for _, _, _, name, _, module in CASES:
        qualified = f"{module}::{name}"
        run = subprocess.run(
            ["cargo", "test", "--locked", "-p", "zeroclaw-runtime", "--lib", qualified,
             "--", "--exact"], cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        (evidence / f"baseline-{name}.log").write_text(run.stdout, encoding="utf-8")
        proved = (run.returncode == 101 and "running 1 test" in run.stdout
                  and f"test {qualified} ... FAILED" in run.stdout)
        results.append({"test": qualified, "base": BASE, "expected_failure_observed": proved,
                        "exit_code": run.returncode})
        print(json.dumps(results[-1]), flush=True)
        if not proved:
            print(run.stdout[-12000:], flush=True)
            raise RuntimeError(f"baseline proof failed: {qualified}")
finally:
    for path, content in original.items():
        (ROOT / path).write_bytes(content)
    (evidence / "baseline-results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
