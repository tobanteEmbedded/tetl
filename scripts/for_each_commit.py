# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

"""
Iterate over every commit on a repo's main branch and run a command on each.

Usage examples:
  python run_on_commits.py https://github.com/owner/repo.git --cmd "mytool --flag"
  python run_on_commits.py https://github.com/owner/repo.git --branch main --cmd "pytest -q"
  python run_on_commits.py https://github.com/owner/repo.git --first-parent --cmd "bash run.sh --rev {commit}"
  python run_on_commits.py https://github.com/owner/repo.git --dest ./repo-work --cmd "echo {commit} {date}"
"""

import argparse
import os
import shlex
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple


def run(cmd: List[str], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, check=check)

def run_out(cmd: List[str], cwd: Path | None = None) -> str:
    return run(cmd, cwd=cwd).stdout.strip()

def ensure_git() -> None:
    try:
        out = run(["git", "--version"]).stdout.strip()
    except Exception as e:
        print("Error: git does not seem to be installed or accessible in PATH.", file=sys.stderr)
        raise
    else:
        print(f"[info] {out}")

def clone_or_open(repo_url: str, dest: Path) -> Path:
    if dest.exists():
        # Reuse if it already looks like a git repo; otherwise bail.
        if (dest / ".git").exists():
            print(f"[info] Using existing repository at {dest}")
        else:
            raise SystemExit(f"Destination {dest} exists but is not a git repository.")
    else:
        print(f"[info] Cloning {repo_url} into {dest} ...")
        # Full history, no shallow clone.
        cp = subprocess.run(["git", "clone", repo_url, str(dest)], text=True)
        if cp.returncode != 0:
            raise SystemExit("Clone failed.")
    return dest

def detect_default_branch(repo: Path) -> str:
    # Try remote HEAD first
    try:
        ref = run_out(["git", "symbolic-ref", "refs/remotes/origin/HEAD"], cwd=repo)
        branch = ref.rsplit("/", 1)[-1]
        print(f"[info] Detected default branch: {branch}")
        return branch
    except subprocess.CalledProcessError:
        # Fallbacks: main then master
        branches = run_out(["git", "branch", "-r"], cwd=repo).splitlines()
        branches = [b.strip().replace("origin/", "") for b in branches if b.strip().startswith("origin/")]
        for cand in ("main", "master"):
            if cand in branches:
                print(f"[info] Falling back to branch: {cand}")
                return cand
        raise SystemExit("Could not detect default branch (tried origin/HEAD, main, master).")

def list_commits(repo: Path, branch: str, first_parent: bool) -> List[str]:
    args = ["git", "rev-list", "--reverse"]
    if first_parent:
        args.append("--first-parent")
    # Use remote tracking ref to avoid relying on a local branch
    args.append(f"origin/{branch}")
    out = run_out(args, cwd=repo)
    commits = [line.strip() for line in out.splitlines() if line.strip()]
    if not commits:
        raise SystemExit(f"No commits found on origin/{branch}.")
    print(f"[info] Found {len(commits)} commits on origin/{branch}")
    return commits

def commit_date(repo: Path, sha: str) -> str:
    return run_out(["git", "show", "-s", "--format=%cI", sha], cwd=repo)

def checkout(repo: Path, ref: str) -> None:
    # Force to avoid local changes interfering
    run(["git", "checkout", "-f", ref], cwd=repo)

def ensure_fresh_remote(repo: Path) -> None:
    print("[info] Fetching latest from origin ...")
    subprocess.run(["git", "fetch", "--all", "--prune"], cwd=repo)

def run_user_cmd(cmd_template: str, repo: Path, sha: str, date_iso: str, env_extra: dict, continue_on_error: bool) -> Tuple[bool, str]:
    env = os.environ.copy()
    env.update(env_extra)
    env["GIT_COMMIT"] = sha
    env["GIT_COMMIT_DATE"] = date_iso
    final_cmd = cmd_template.format(commit=sha, date=date_iso)
    print(f"[run ] {final_cmd}")
    # Use shell to allow pipelines/redirects; user-provided string is executed as-is.
    proc = subprocess.run(final_cmd, shell=True, cwd=repo, text=True, env=env)
    ok = proc.returncode == 0
    if not ok:
        msg = f"Command failed with exit code {proc.returncode}"
        print(f"[fail] {msg}")
        if not continue_on_error:
            raise SystemExit(msg)
        return False, msg
    return True, "ok"

def main():
    p = argparse.ArgumentParser(description="Clone a repo and run a command on every commit in main branch history.")
    p.add_argument("repo", help="Git repository URL (https:// or git@)")
    p.add_argument("--dest", default=None, help="Destination folder (default: ./<repo-name>)")
    p.add_argument("--branch", default=None, help="Branch name to traverse (default: auto-detect origin/HEAD or main/master)")
    p.add_argument("--first-parent", action="store_true", help="Follow only the first-parent history (linearize merges).")
    p.add_argument("--cmd", required=True, help="Command to run at each commit. You can use {commit} and {date} placeholders.")
    p.add_argument("--continue-on-error", action="store_true", help="Continue even if the command fails on a commit.")
    p.add_argument("--dry-run", action="store_true", help="List commits and commands without checking out or running.")
    args = p.parse_args()

    ensure_git()

    repo_name = Path(args.repo.rstrip("/")).stem.replace(".git", "")
    dest = Path(args.dest) if args.dest else Path.cwd() / repo_name
    repo = clone_or_open(args.repo, dest)

    ensure_fresh_remote(repo)

    branch = args.branch or detect_default_branch(repo)
    commits = list_commits(repo, branch, args.first_parent)

    results = []
    try:
        for i, sha in enumerate(commits, 1):
            date_iso = commit_date(repo, sha)

            if args.dry_run:
                preview = args.cmd.format(commit=sha, date=date_iso)
                print(f"[plan] {i}/{len(commits)} {sha} @ {date_iso} -> {preview}")
                continue

            print(f"[step] {i}/{len(commits)} Checking out {sha} ({date_iso})")
            checkout(repo, sha)
            ok, msg = run_user_cmd(args.cmd, repo, sha, date_iso, {}, args.continue_on_error)
            results.append((sha, date_iso, ok, msg))

    except KeyboardInterrupt:
        print("\n[info] Interrupted by user.")

    finally:
        # Try to restore to the branch tip for convenience
        try:
            checkout(repo, f"origin/{branch}")
            # Create/fast-forward a local branch named {branch} if it doesn't exist
            # (best-effort; ignore errors)
            subprocess.run(["git", "switch", "-C", branch], cwd=repo)
            subprocess.run(["git", "merge", "--ff-only", f"origin/{branch}"], cwd=repo)
        except Exception:
            pass

    # Summary
    if not args.dry_run:
        total = len(results)
        ok = sum(1 for _, _, s, _ in results if s)
        fail = total - ok
        print("\n=== Summary ===")
        print(f"Total commits processed: {total}")
        print(f"Successful runs       : {ok}")
        print(f"Failed runs           : {fail}")
        if fail:
            print("\nFailures:")
            for sha, date_iso, s, msg in results:
                if not s:
                    print(f"  {sha} @ {date_iso}: {msg}")

if __name__ == "__main__":
    main()
