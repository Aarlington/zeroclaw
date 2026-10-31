"""Validate the installer entrypoint's selected download target, offline."""
import json, pathlib, subprocess, sys, tempfile
repo, out = (pathlib.Path(p).resolve() for p in sys.argv[1:])
out.mkdir(parents=True, exist_ok=True)
cases = [("glibc-with-musl-probe", 0, "musl libc", 1, "gnu"),
         ("glibc-ldd-only", 127, "ldd (GNU libc) 2.39", 0, "gnu"),
         ("Alpine-musl", 1, "musl libc (x86_64)", 1, "musl")]
results = []
with tempfile.TemporaryDirectory(prefix="zeroclaw-libc-proof-") as tmp:
    root = pathlib.Path(tmp)
    for name, getconf_status, ldd_text, ldd_status, expected in cases:
        case = root / name
        case.mkdir()
        def stub(name, content):
            p = case / name
            p.write_text("#!/bin/sh\n" + content + "\n")
            p.chmod(0o755)
        stub("getconf", f"exit {getconf_status}")
        stub("ldd", f"printf '%s\\n' '{ldd_text}'; exit {ldd_status}")
        stub("uname", 'case "$1" in -s) echo Linux;; -m) echo x86_64;; *) exit 90;; esac')
        stub("curl", 'case "$*" in *https://api.github.com/repos/zeroclaw-labs/zeroclaw/releases/latest*) printf \'{"tag_name":"v0.8.7"}\\n\';; *) exit 91;; esac')
        env = {"PATH": f"{case}:/usr/bin:/bin", "HOME": str(case), "SHELL": "/bin/sh", "LANG": "C.UTF-8"}
        p = subprocess.run(["/bin/sh", str(repo / "install.sh"), "--prebuilt", "--dry-run", "--skip-quickstart", "--no-modify-path"], cwd=case, env=env, input="", text=True, capture_output=True, timeout=20)
        output = p.stdout + p.stderr
        (out / (name + ".log")).write_text(output.replace(str(root), "<isolated-fixture>"))
        assert p.returncode == 0, output
        triple = f"x86_64-unknown-linux-{expected}"
        assert f"Platform: {triple}" in output and f"zeroclaw-{triple}.tar.gz" in output, output
        results.append({"fixture": name, "target": triple, "exit": p.returncode})
(out / "receipt.json").write_text(json.dumps({"results": results, "network": False, "real_install": False}, indent=2) + "\n")
print(json.dumps({"entrypoint_cases": len(results), "result": "PASS"}))
