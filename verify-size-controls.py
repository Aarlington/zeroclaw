"""Fault-inject copies only; preserve the reviewed source and release workflow."""
import hashlib, json, pathlib, shutil, subprocess, sys, tempfile
repo, out = (pathlib.Path(p).resolve() for p in sys.argv[1:])
out.mkdir(parents=True, exist_ok=True)
script = (repo / "scripts/ci/check_binary_size.sh").read_bytes()
test = (repo / "scripts/ci/check_binary_size_test.py").read_bytes()
variants = {
    "guard-disabled": script.replace(b'if [ "$SIZE" -gt "$HARD_LIMIT" ]; then', b'if false; then'),
    "equal-cap-rejected": script.replace(b'if [ "$SIZE" -gt "$HARD_LIMIT" ]; then', b'if [ "$SIZE" -ge "$HARD_LIMIT" ]; then'),
}
results = []
with tempfile.TemporaryDirectory(prefix="zeroclaw-size-controls-") as tmp:
    root = pathlib.Path(tmp)
    for name, changed in variants.items():
        assert changed != script
        case = root / name
        case.mkdir()
        (case / "check_binary_size.sh").write_bytes(changed)
        (case / "check_binary_size_test.py").write_bytes(test)
        p = subprocess.run([sys.executable, str(case / "check_binary_size_test.py"), "-v"], capture_output=True, text=True, timeout=30)
        output = p.stdout + p.stderr
        (out / (name + ".log")).write_text(output.replace(str(root), "<control-fixture>"))
        assert p.returncode == 1 and "FAIL:" in output and "ERROR:" not in output, output
        if name == "guard-disabled":
            assert "FAIL: test_default_rejects_one_byte_over" in output
            assert "FAIL: test_smaller_override_is_enforced" in output
        else:
            assert "FAIL: test_release_override_keeps_exact_boundary" in output
        results.append({"control": name, "exit": p.returncode, "assertion_failure_confirmed": True})
assert (repo / "scripts/ci/check_binary_size.sh").read_bytes() == script
assert (repo / "scripts/ci/check_binary_size_test.py").read_bytes() == test
p = subprocess.run([sys.executable, str(repo / "scripts/ci/check_binary_size_test.py"), "-v"], capture_output=True, text=True, timeout=30)
assert p.returncode == 0, p.stdout + p.stderr
(out / "final-suite.log").write_text(p.stdout + p.stderr)
(out / "receipt.json").write_text(json.dumps({"controls": results, "final_suite": "7 tests PASS", "source_sha256": hashlib.sha256(script).hexdigest(), "source_unchanged": True}, indent=2) + "\n")
print(json.dumps({"controls_rejected": len(results), "final_suite": "7 tests PASS", "source_unchanged": True}))
