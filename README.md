# Installer and release-size evidence

Synthetic local checks on WSL Ubuntu with `/bin/sh` (dash), Bash and Python 3.12.
The exact source revisions and file hashes are in `source-manifest.json`.
These checks use no provider accounts, real credentials, paid runs or release dispatch.

## #12153: libc detection

The committed `scripts/ci/install_target_triple_test.sh` passes 27 cases: 18 existing
target cases and nine production-probe cases, each also checking x86_64 and aarch64
mapping. With the original detector, three glibc-with-musl cases fail (24 pass).
The probe fixtures use the installer's POSIX pipeline semantics; the Bash runner's
pipefail is intentionally not inherited by a probe fixture because musl ldd may
print its version and return nonzero. No behavior assertion was removed.

`verify-libc.py` additionally runs three complete `--prebuilt --dry-run` entrypoints
with controlled getconf/ldd/uname and release metadata. It checks the platform and
download URL. No archive is fetched and no binary is installed. Native Alpine and
ARM execution are not claimed. The updater's target logic (#12156) remains separate.

```sh
bash scripts/ci/install_target_triple_test.sh
python3 verify-libc.py /path/to/12153-checkout /tmp/libc-proof
```

## #11580: stale advisory removal

The committed process suite passes seven tests covering 13 calls against real
sparse files. It covers missing files, former warning thresholds, default and
overridden caps, exact-cap acceptance, one-byte-over refusal and summary output.
Two mutated copies are rejected: disabling the hard gate and rejecting equality.
The original source stays unchanged and the final seven-test rerun passes.

The CI YAML parses with PyYAML 6.0.1. Structural comparison confirms exactly one
new test step in the existing required Repository Structure job. The Stable release
workflow is byte-identical to base, including its 80 MiB cap. No new artifact-size
measurement, reduction, release decision or full #11580 closeout is claimed.

```sh
python3 scripts/ci/check_binary_size_test.py -v
python3 verify-size-controls.py /path/to/11580-checkout /tmp/size-controls
```
