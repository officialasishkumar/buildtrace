"""Summarise census reports: who served the bytes, and which installs reached beyond the package registry.

  python3 census/summarize.py census/out > census/RESULTS.md
"""
import collections, glob, json, os, sys

REGISTRY = {
    "npm": {"registry.npmjs.org", "registry.yarnpkg.com"},
    "pypi": {"pypi.org", "files.pythonhosted.org"},
}


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1000:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} TB"


def load(root):
    sets = {}
    for d in sorted(glob.glob(os.path.join(root, "*/"))):
        name = os.path.basename(d.rstrip("/"))
        eco = "pypi" if name.startswith("pypi") else "npm"
        reps, failed = [], []
        for f in sorted(glob.glob(os.path.join(d, "*.json"))):
            r = json.load(open(f))
            r["_pkg"] = os.path.basename(f)[:-5]
            reps.append(r)
        failed = [os.path.basename(f)[:-12] for f in glob.glob(os.path.join(d, "*.json.failed"))]
        sets[name] = (eco, reps, failed)
    return sets


def summarize(name, eco, reps, failed):
    out = [f"## {name}\n"]
    reg = REGISTRY[eco]
    total = collections.Counter()
    by_org = collections.Counter()
    by_cc = collections.Counter()
    off = []  # (pkg, host, bytes, process, plaintext)
    plain_pkgs = set()
    exits = collections.Counter()
    for r in reps:
        exits["ok" if r.get("exit_code", 0) == 0 else "install failed"] += 1
        for h in r.get("hosts") or []:
            if h.get("role") == "dns":
                continue
            b = h.get("bytes_in", 0) + h.get("bytes_out", 0)
            total[r["_pkg"]] += b
            by_org[h.get("org") or h.get("as_name") or "unknown"] += b
            by_cc[h.get("country") or "??"] += b
            plain = h.get("port") == 80
            if plain:
                plain_pkgs.add(r["_pkg"])
            if h.get("name") not in reg:
                off.append((r["_pkg"], h.get("name"), b, ",".join(h.get("processes") or []), plain, h.get("org") or "", h.get("country") or ""))
    allb = sum(total.values()) or 1
    off_pkgs = sorted({o[0] for o in off})
    out.append(f"{len(reps)} installs traced ({exits['install failed']} exited non-zero), {len(failed)} produced no report; {human(allb)} downloaded in total.\n")
    out.append(f"- **{len(off_pkgs)} of {len(reps)}** installs contacted a host other than the registry ({', '.join(sorted(reg))}).")
    out.append(f"- **{len(plain_pkgs)}** used plaintext HTTP for at least one connection.")
    out.append("- Bytes by operator: " + ", ".join(f"{k} {100*v/allb:.0f}%" for k, v in by_org.most_common(5)))
    out.append("- Bytes by country of network registration: " + ", ".join(f"{k} {100*v/allb:.0f}%" for k, v in by_cc.most_common(5)) + "\n")
    if off:
        out.append("| package | host contacted outside the registry | bytes | operator | cc | process | plaintext |")
        out.append("|---|---|---:|---|---|---|---|")
        for pkg, host, b, proc, plain, org, cc in sorted(off, key=lambda x: (-x[2], x[0])):
            out.append(f"| {pkg} | {host} | {human(b)} | {org} | {cc} | {proc} | {'yes' if plain else ''} |")
        out.append("")
    if failed:
        out.append("No report (timeout or crash): " + ", ".join(sorted(failed)) + "\n")
    return "\n".join(out)


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "census/out"
    print("# Install census: who serves popular packages, and what installs fetch outside the registry\n")
    print("Each package was installed alone, in a fresh container with an empty cache, under `buildtrace run`. "
          "Host names come from TLS SNI, DNS answers and HTTP Host headers; operators and countries from iptoasn.com. "
          "DNS lookups are not counted as downloads.\n")
    for name, (eco, reps, failed) in load(root).items():
        print(summarize(name, eco, reps, failed))


if __name__ == "__main__":
    main()
