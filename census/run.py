"""Install popular packages one at a time in a fresh container under buildtrace, and keep each JSON report.

  docker build --build-arg BASE=node:22-bookworm   -t buildtrace-census:node   census/
  docker build --build-arg BASE=python:3.12-bookworm -t buildtrace-census:python census/
  python3 census/run.py --list census/lists/npm-top300.txt --eco npm --out census/out/npm
  python3 census/run.py --list census/lists/pypi-top200.txt --eco pypi --out census/out/pypi
  python3 census/summarize.py census/out > census/RESULTS.md

Each install starts from an empty directory and an empty package cache, so every byte it needs is fetched.
"""
import argparse, concurrent.futures as cf, os, re, subprocess

CMD = {
    "npm": ("buildtrace-census:node", "mkdir p && cd p && npm init -y >/dev/null && npm install --no-audit --no-fund {pkg}"),
    "pypi": ("buildtrace-census:python", "pip install --no-cache-dir --disable-pip-version-check -q {pkg}"),
}


def safe(name):
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def one(eco, pkg, out, timeout):
    image, cmd = CMD[eco]
    dst = os.path.join(out, safe(pkg) + ".json")
    if os.path.exists(dst):
        return pkg, "cached"
    name = "btc-" + safe(pkg).lower()[:40] + "-" + eco
    run = ["docker", "run", "--rm", "--name", name, "--cap-add", "NET_RAW", "--cap-add", "SYS_PTRACE",
           "-v", f"{os.path.abspath(out)}:/out", image,
           "buildtrace", "run", "--json", f"/out/{safe(pkg)}.json", "--", "sh", "-c", cmd.format(pkg=pkg)]
    try:
        p = subprocess.run(run, capture_output=True, text=True, timeout=timeout)
        status = f"exit {p.returncode}"
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        status = "timeout"
    if not os.path.exists(dst):
        open(dst + ".failed", "w").write(status)
    return pkg, status


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", required=True)
    ap.add_argument("--eco", choices=CMD, required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--timeout", type=int, default=600)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    pkgs = [l.strip() for l in open(a.list) if l.strip() and not l.startswith("#")]
    with cf.ThreadPoolExecutor(a.workers) as ex:
        for i, (pkg, status) in enumerate(ex.map(lambda p: one(a.eco, p, a.out, a.timeout), pkgs), 1):
            print(f"[{i}/{len(pkgs)}] {pkg}: {status}", flush=True)


if __name__ == "__main__":
    main()
