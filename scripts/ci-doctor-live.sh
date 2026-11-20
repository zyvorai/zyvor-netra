#!/usr/bin/env bash
# Netra — netra-doctor host readiness, end to end (docs/host-readiness.md)
#
# The real binary against (a) an empty filesystem root, which must fail loudly with
# remediation text and exit 2, and (b) on Linux, this very host, which must pass
# every check the agent needs (kernel, TCX, cgroup v2, bpffs, BTF, tracefs, drop
# reasons) with exit 0 when they are required. The JSON report and the human
# report must agree with each other and with the exit code.
#
# Usage:
#   ./scripts/ci-doctor-live.sh        # on Linux also checks the host itself
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
D="$(mktemp -d "${TMPDIR:-/tmp}/netra-doctor.XXXXXX")"
trap 'rm -rf "$D"' EXIT

echo "==> build netra-doctor"
CGO_ENABLED=0 go build -trimpath -o "$D/netra-doctor" ./cmd/netra-doctor

echo "==> an empty root fails loudly, with remediation, and exits 2"
mkdir "$D/empty"
rc=0; "$D/netra-doctor" -json -root "$D/empty" >"$D/empty.json" || rc=$?
[[ "$rc" == 2 ]] || { echo "empty root exited $rc, want 2" >&2; cat "$D/empty.json" >&2; exit 1; }
python3 - "$D/empty.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
s = r["summary"]
assert s["fail"] >= 1, ("an empty root must produce failures", s)
assert sum(s.values()) == len(r["checks"]), ("summary counts must add up to the checks", s, len(r["checks"]))
ids = {c["id"] for c in r["checks"]}
for want in ("os", "kernel", "cgroup-v2", "bpffs", "btf", "tracefs", "drop-reasons", "capabilities"):
    assert want in ids, ("missing check", want, sorted(ids))
failed = [c for c in r["checks"] if c["status"] == "fail"]
assert all(c.get("remediation") for c in failed), ("a failing check without remediation text", [c["id"] for c in failed if not c.get("remediation")])
print("    %d checks, %d fail, every failure carries remediation" % (len(r["checks"]), s["fail"]))
PY

echo "==> the human report agrees with the JSON summary"
"$D/netra-doctor" -root "$D/empty" >"$D/empty.txt" || true
want="$(python3 -c "import json;s=json.load(open('$D/empty.json'))['summary'];print('summary: pass=%d warn=%d fail=%d info=%d'%(s['pass'],s['warn'],s['fail'],s['info']))")"
grep -qxF "$want" "$D/empty.txt" || { echo "human summary differs from JSON: want '$want'" >&2; cat "$D/empty.txt" >&2; exit 1; }
echo "    $want"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "==> (skipping the host check: needs Linux)"
  echo "==> PASS doctor live (empty root only)"
  exit 0
fi

echo "==> this host passes what the agent needs"
rc=0; "$D/netra-doctor" -json -require-tcx -require-drop-reasons >"$D/host.json" || rc=$?
python3 - "$D/host.json" "$rc" <<'PY'
import json, sys
r, rc = json.load(open(sys.argv[1])), int(sys.argv[2])
s = r["summary"]
by = {c["id"]: c for c in r["checks"]}
bad = {i: (c["status"], c["detail"]) for i, c in by.items() if c["status"] == "fail"}
assert not bad, ("the host fails checks the agent needs", bad)
assert rc == 0, ("no failures but a non-zero exit", rc)
for want in ("os", "arch", "kernel", "tcx", "cgroup-v2", "bpffs", "btf", "tracefs", "drop-reasons"):
    assert want in by, ("missing check", want)
    assert by[want]["status"] in ("pass", "info", "warn"), (want, by[want])
assert by["os"]["status"] == "pass" and by["cgroup-v2"]["status"] == "pass", (by["os"], by["cgroup-v2"])
print("    kernel %s: pass=%d warn=%d fail=%d info=%d" % (r["kernelRelease"], s["pass"], s["warn"], s["fail"], s["info"]))
PY

echo "==> -strict turns warnings into a failing exit"
warns="$(python3 -c "import json;print(json.load(open('$D/host.json'))['summary']['warn'])")"
rc=0; "$D/netra-doctor" -strict -require-tcx -require-drop-reasons >/dev/null || rc=$?
if [[ "$warns" -gt 0 ]]; then want=2; else want=0; fi
[[ "$rc" == "$want" ]] || { echo "-strict exited $rc with $warns warnings, want $want" >&2; exit 1; }
echo "    warnings=$warns, -strict exit=$rc"

echo "==> PASS doctor live"
