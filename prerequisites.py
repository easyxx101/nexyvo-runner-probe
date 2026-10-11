"""Reviewed generic native Linux allocated-capacity checks; no application inputs."""
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil

GIB = 1024**3

def hierarchy(cgroup, mountinfo):
    lines = cgroup.strip().splitlines()
    if len(lines) != 1 or not lines[0].startswith("0::/"):
        raise RuntimeError("Unified cgroup v2 required")
    group = lines[0][3:]
    if any(p in (".", "..") for p in group.split("/")) or " (deleted)" in group:
        raise RuntimeError("Invalid cgroup membership")
    mounts = [line.split() for line in mountinfo.splitlines() if " - cgroup2 " in line]
    if len(mounts) != 1 or len(mounts[0]) < 10 or mounts[0][3] != "/" or "\\" in mounts[0][4]:
        raise RuntimeError("One full cgroup v2 hierarchy mount required")
    mount = PurePosixPath(mounts[0][4])
    if not mount.is_absolute():
        raise RuntimeError("Invalid cgroup mount")
    node = mount / group.lstrip("/")
    nodes = [node]
    while node != mount:
        node = node.parent
        nodes.append(node)
    return nodes


def quota_limit(raw):
    fields = raw.split()
    if (len(fields) != 2 or not re.fullmatch(r"[1-9][0-9]*", fields[1])
            or fields[0] != "max" and not re.fullmatch(r"[1-9][0-9]*", fields[0])):
        raise RuntimeError("Invalid CPU quota")
    return None if fields[0] == "max" else int(fields[0]) // int(fields[1])


def effective_capacity(nodes, affinity, memory_total, read):
    if affinity <= 0 or memory_total <= 0:
        raise RuntimeError("Invalid host capacity")
    root_controllers = read(nodes[-1] / "cgroup.controllers").split()
    if not {"cpu", "memory"} <= set(root_controllers):
        raise RuntimeError("CPU and memory accounting required")
    # A cgroup namespace can present a constrained subtree as / in both
    # proc membership and mountinfo. Real hierarchy roots have neither limit
    # file; visible root limits mean ancestors may be hidden. Refuse rather
    # than reporting affinity/physical memory as allocated runner capacity.
    for filename in ("cpu.max", "memory.max"):
        try:
            read(nodes[-1] / filename)
        except FileNotFoundError:
            continue
        raise RuntimeError("Namespaced cgroup root cannot establish full capacity")
    cpus, memory = affinity, memory_total
    quotas = []
    memory_limits = []
    for index, node in enumerate(nodes):
        # cpu.max/memory.max intentionally do not exist on the root cgroup.
        if index == len(nodes)-1:
            continue
        enabled = read(nodes[index+1] / "cgroup.subtree_control").split()
        if "cpu" in enabled:
            quota = quota_limit(read(node / "cpu.max"))
            quotas.append(quota)
            if quota is not None:
                cpus = min(cpus, quota)
        if "memory" in enabled:
            raw = read(node / "memory.max").strip()
            memory_limits.append(None if raw == "max" else int(raw) if re.fullmatch(r"[1-9][0-9]*", raw) else -1)
            if raw != "max":
                if not re.fullmatch(r"[1-9][0-9]*", raw):
                    raise RuntimeError("Invalid memory limit")
                memory = min(memory, int(raw))
    return {"affinity_cpus": affinity, "allocated_cpus": cpus,
            "root_limits_absent": True,
            "visible_cpu_quotas": quotas, "hierarchy_levels_checked": len(nodes),
            "visible_memory_limits": memory_limits,
            "memory_total_bytes": memory_total, "allocated_memory_bytes": memory,
            "quota_scope": "CURRENT_CGROUP_AND_VISIBLE_ANCESTORS"}


def preflight():
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("Native Linux x64 required")
    read = lambda path: Path(path).read_text()
    nodes = hierarchy(read("/proc/self/cgroup"), read("/proc/self/mountinfo"))
    memory = re.findall(r"^MemTotal:\s+([0-9]+) kB$", read("/proc/meminfo"), re.MULTILINE)
    if len(memory) != 1:
        raise RuntimeError("Physical memory measurement unavailable")
    report = effective_capacity(nodes, len(os.sched_getaffinity(0)), int(memory[0])*1024, read)
    sdk = Path(os.environ["ANDROID_HOME"])
    report.update(platform="LINUX_X64_KVM", kvm_access=os.access("/dev/kvm", os.R_OK | os.W_OK),
                  sdk_free_bytes=shutil.disk_usage(sdk).free,
                  evidence_cli_available=shutil.which("gh") is not None,
                  timeout_available=shutil.which("timeout") is not None,
                  existing_licenses=(sdk / "licenses").is_dir(),
                  sdkmanager_executable=os.access(sdk / "cmdline-tools/latest/bin/sdkmanager", os.X_OK))
    report["status"] = "PASSED" if (report["allocated_cpus"] >= 4
        and report["allocated_memory_bytes"] >= 8*GIB and report["kvm_access"]
        and report["sdk_free_bytes"] >= 16*GIB and report["sdkmanager_executable"]
        and report["evidence_cli_available"] and report["timeout_available"]
        and report["existing_licenses"]) else "FAILED"
    return report
