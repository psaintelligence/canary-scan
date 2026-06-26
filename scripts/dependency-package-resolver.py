#!/usr/bin/env python3
"""Verify that system package names resolve across apt, rpm (dnf/yum), and apk package managers."""

import sys
import shutil
import subprocess
from pathlib import Path

# Add src/ to sys.path
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir / "src"))

from canary_scan.lib.config import DEPS, SPECIALIZED_DEPS, PACKAGE_MAPPINGS
from canary_scan.lib.deps import parse_hint

# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"


def check_docker_available() -> bool:
    """Check if Docker daemon is available and running."""
    if not shutil.which("docker"):
        return False
    try:
        res = subprocess.run(
            ["docker", "ps"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return res.returncode == 0
    except Exception:
        return False


def detect_package_manager() -> tuple[str, str] | tuple[None, None]:
    """Detect local package manager and its system type."""
    if shutil.which("apt-cache"):
        return "apt", "apt"
    if shutil.which("dnf"):
        return "dnf", "rpm"
    if shutil.which("yum"):
        return "yum", "rpm"
    if shutil.which("apk"):
        return "apk", "apk"
    return None, None


def query_package_locally(manager: str, pkg: str) -> bool:
    """Query package presence in the local package manager."""
    try:
        if manager == "apt":
            res = subprocess.run(
                ["apt-cache", "show", pkg],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return res.returncode == 0
        elif manager in ("dnf", "yum"):
            res = subprocess.run(
                [manager, "info", "-q", pkg],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return res.returncode == 0
        elif manager == "apk":
            res = subprocess.run(
                ["apk", "search", "-q", f"^{pkg}$"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            return res.returncode == 0 and pkg in res.stdout
    except Exception:
        return False
    return False


def query_packages_in_docker(mgr_type: str, pkgs: list[str]) -> dict[str, bool]:
    """Query all package names inside a Docker container for a given distro."""
    results = {}
    
    # We choose standard official containers for validation
    if mgr_type == "apk":
        # Alpine Linux
        cmd = [
            "docker", "run", "--rm", "alpine:latest",
            "sh", "-c", f"apk update >/dev/null && for pkg in {' '.join(pkgs)}; do apk search -q \"$pkg\" | grep -qx \"$pkg\" && echo \"$pkg:OK\" || echo \"$pkg:FAIL\"; done"
        ]
    elif mgr_type == "apt":
        # Ubuntu Linux
        cmd = [
            "docker", "run", "--rm", "ubuntu:latest",
            "sh", "-c", f"apt-get update >/dev/null 2>&1 && for pkg in {' '.join(pkgs)}; do apt-cache show \"$pkg\" >/dev/null 2>&1 && echo \"$pkg:OK\" || echo \"$pkg:FAIL\"; done"
        ]
    elif mgr_type == "rpm":
        # Fedora Linux (rpm-based with dnf)
        cmd = [
            "docker", "run", "--rm", "fedora:latest",
            "sh", "-c", f"dnf makecache >/dev/null && for pkg in {' '.join(pkgs)}; do dnf info -q \"$pkg\" >/dev/null 2>&1 && echo \"$pkg:OK\" || echo \"$pkg:FAIL\"; done"
        ]
    else:
        return {}

    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if ":" in line:
                    pkg, status = line.split(":", 1)
                    results[pkg.strip()] = (status.strip() == "OK")
    except Exception as e:
        print(f"  {RED}! Error querying docker for {mgr_type}: {e}{RESET}")

    # Fallback to False for anything missing
    for pkg in pkgs:
        if pkg not in results:
            results[pkg] = False
    return results


def main():
    print(f"{CYAN}=== System Dependencies Resolver Verification ==={RESET}\n")

    # 1. Gather all configured system dependencies
    sys_deps = set()
    all_deps = dict(DEPS)
    all_deps.update(SPECIALIZED_DEPS)

    for name, (tier, hint, binary, purpose) in all_deps.items():
        tag, val = parse_hint(hint)
        if tag in ("apt|rpm|apk", "apt|rpm"):
            sys_deps.add(val)

    # 2. Static validation: verify mappings exist
    print(f"{CYAN}[Step 1/2] Statically verifying mappings in PACKAGE_MAPPINGS...{RESET}")
    static_errors = 0
    for dep in sorted(sys_deps):
        if dep not in PACKAGE_MAPPINGS:
            print(f"  {RED}✗ Missing mapping for package:{RESET} {dep}")
            static_errors += 1
        else:
            mapping = PACKAGE_MAPPINGS[dep]
            missing_types = [t for t in ("apt", "rpm", "apk") if t not in mapping]
            if missing_types:
                print(f"  {RED}✗ Package {dep} is missing mappings for types:{RESET} {', '.join(missing_types)}")
                static_errors += len(missing_types)

    if static_errors > 0:
        print(f"\n{RED}Static validation failed with {static_errors} error(s). Please define all mappings.{RESET}")
        sys.exit(1)
    else:
        print(f"  {GREEN}✓ All package mappings are statically defined.{RESET}\n")

    # 3. Live validation
    has_docker = check_docker_available()

    if has_docker:
        print(f"{CYAN}[Step 2/2] Running Multi-OS Live Verification via Docker...{RESET}")
        
        # Collect lists of packages per system type (skipping custom hints starting with '[')
        apt_list = sorted({PACKAGE_MAPPINGS[dep]["apt"] for dep in sys_deps if not PACKAGE_MAPPINGS[dep]["apt"].startswith("[")})
        rpm_list = sorted({PACKAGE_MAPPINGS[dep]["rpm"] for dep in sys_deps if not PACKAGE_MAPPINGS[dep]["rpm"].startswith("[")})
        apk_list = sorted({PACKAGE_MAPPINGS[dep]["apk"] for dep in sys_deps if not PACKAGE_MAPPINGS[dep]["apk"].startswith("[")})
        
        print(f"  Querying {CYAN}apt{RESET} (Ubuntu)...")
        apt_results = query_packages_in_docker("apt", apt_list)
        
        print(f"  Querying {CYAN}rpm{RESET} (Fedora)...")
        rpm_results = query_packages_in_docker("rpm", rpm_list)
        
        print(f"  Querying {CYAN}apk{RESET} (Alpine)...")
        apk_results = query_packages_in_docker("apk", apk_list)
        
        print(f"\n{CYAN}--- Resolution Results ---{RESET}")
        
        errors = 0
        for dep in sorted(sys_deps):
            mapped_apt = PACKAGE_MAPPINGS[dep]["apt"]
            mapped_rpm = PACKAGE_MAPPINGS[dep]["rpm"]
            mapped_apk = PACKAGE_MAPPINGS[dep]["apk"]
            
            apt_ok = True if mapped_apt.startswith("[") else apt_results.get(mapped_apt, False)
            rpm_ok = True if mapped_rpm.startswith("[") else rpm_results.get(mapped_rpm, False)
            apk_ok = True if mapped_apk.startswith("[") else apk_results.get(mapped_apk, False)
            
            print(f"  Package: {CYAN}{dep:<24}{RESET}")
            
            status_apt = f"{GREEN}found{RESET}" if apt_ok else f"{RED}not found{RESET}"
            status_rpm = f"{GREEN}found{RESET}" if rpm_ok else f"{RED}not found{RESET}"
            status_apk = f"{GREEN}found{RESET}" if apk_ok else f"{RED}not found{RESET}"
            
            print(f"    - apt : {mapped_apt:<24} -> {status_apt}")
            print(f"    - rpm : {mapped_rpm:<24} -> {status_rpm}")
            print(f"    - apk : {mapped_apk:<24} -> {status_apk}")
            
            if not (apt_ok and rpm_ok and apk_ok):
                errors += 1
                
        print("")
        if errors > 0:
            print(f"{YELLOW}Multi-OS Live verification completed with warning: {errors} package mapping(s) could not be resolved on all platforms.{RESET}")
            sys.exit(0)
        else:
            print(f"{GREEN}Multi-OS Live verification passed. All packages successfully resolved on all platforms.{RESET}")
            sys.exit(0)
            
    else:
        print(f"{CYAN}[Step 2/2] Running Local Live Verification...{RESET}")
        print(f"  {YELLOW}! Docker not available. Verifying local package manager only.{RESET}")
        
        local_mgr, mgr_type = detect_package_manager()
        if not local_mgr:
            print(f"  {YELLOW}! No supported local package manager found. Skipping live verification.{RESET}")
            sys.exit(0)

        print(f"  Detected local manager: {CYAN}{local_mgr}{RESET} (type: {CYAN}{mgr_type}{RESET})")
        print(f"  Querying package repository cache...\n")

        live_errors = 0
        for dep in sorted(sys_deps):
            resolved_name = PACKAGE_MAPPINGS[dep][mgr_type]
            if resolved_name.startswith("["):
                print(f"  {GREEN}✓{RESET} {dep:<28} -> resolved as {YELLOW}{resolved_name:<28}{RESET} [custom hint]")
                continue
            is_ok = query_package_locally(local_mgr, resolved_name)
            if is_ok:
                print(f"  {GREEN}✓{RESET} {dep:<28} -> resolved as {GREEN}{resolved_name:<28}{RESET} [found]")
            else:
                print(f"  {RED}✗{RESET} {dep:<28} -> resolved as {RED}{resolved_name:<28}{RESET} [not found]")
                live_errors += 1

        print("")
        if live_errors > 0:
            print(f"{YELLOW}Live verification completed: {live_errors} package(s) could not be resolved locally.{RESET}")
            sys.exit(0)
        else:
            print(f"{GREEN}Live verification passed. All packages successfully resolved locally.{RESET}")
            sys.exit(0)


if __name__ == "__main__":
    main()
