import re

_MALICIOUS_PATTERNS = [
    (re.compile(r'connect\('),                         "Network connection attempt"),
    (re.compile(r'socket\(AF_INET'),                   "IPv4 socket creation"),
    (re.compile(r'socket\(AF_INET6'),                  "IPv6 socket creation"),
    (re.compile(r'openat?\(.*"/etc/shadow"'),          "Shadow password file access"),
    (re.compile(r'ptrace\(PTRACE_ATTACH'),             "Process injection attempt"),
    (re.compile(r'mount\('),                           "Filesystem mount attempt"),
    (re.compile(r'init_module\(|finit_module\('),      "Kernel module load attempt"),
    (re.compile(r'write\(.*"\\177ELF'),                "Writing ELF header — binary infection"),
]

_SUSPICIOUS_PATTERNS = [
    (re.compile(r'openat?\(.*"/etc/passwd"'),          "Credential file read"),
    (re.compile(r'openat?\(.*"/proc/self/mem"'),       "Self-memory manipulation"),
    (re.compile(r'chmod\(.*0[0-9]*[67][0-9]*\)'),     "Making file executable"),
    (re.compile(r'unlink\(|unlinkat\('),               "File deletion"),
    (re.compile(r'bind\('),                            "Socket bind (listener)"),
    (re.compile(r'openat?\(.*"/targets/[^"]+",.*O_(?:WRONLY|RDWR)'),
     "Attempted write to decoy target file — possible file infector"),
    (re.compile(r'openat?\(.*"decoy_[^"]*",.*O_(?:WRONLY|RDWR|CREAT)'),
     "Attempted write to decoy target file — possible file infector"),
    (re.compile(r'sendfile\('),
     "File content copied via sendfile — possible file infector"),
    (re.compile(r'openat?\(.*O_(?:WRONLY|RDWR|CREAT).*=\s*-1\s*E(?:PERM|ACCES|ROFS)'),
     "Blocked file write attempt — possible file infector"),
    (re.compile(r'write\(.*=\s*-1\s*E(?:PERM|ROFS)'),
     "Write syscall blocked by read-only filesystem"),
]

_FORK_BOMB_THRESHOLD   = 30
_EXEC_CHAIN_THRESHOLD  = 8
# A Unix virus opens many files for writing (to infect them); 3+ is suspicious
_WRITE_ATTEMPT_THRESHOLD = 3


def _analyze_trace(trace_text: str) -> dict:
    """Parse strace output and return verdict, score, behaviors, syscall counts."""
    behaviors       = []
    syscall_counts  = {}
    malicious_hits  = []
    suspicious_hits = []

    lines = trace_text.splitlines()

    for line in lines:
        for syscall in ("fork", "clone", "execve", "connect", "socket"):
            if f"{syscall}(" in line:
                syscall_counts[syscall] = syscall_counts.get(syscall, 0) + 1

        for pattern, label in _MALICIOUS_PATTERNS:
            if pattern.search(line) and label not in malicious_hits:
                malicious_hits.append(label)

        for pattern, label in _SUSPICIOUS_PATTERNS:
            if pattern.search(line) and label not in suspicious_hits:
                suspicious_hits.append(label)

    fork_count = syscall_counts.get("fork", 0) + syscall_counts.get("clone", 0)
    exec_count = syscall_counts.get("execve", 0)

    write_attempts = sum(
        1 for line in lines
        if re.search(r'openat?\(.*O_(?:WRONLY|RDWR)', line)
    )
    if write_attempts >= _WRITE_ATTEMPT_THRESHOLD:
        suspicious_hits.append(
            f"Mass file write attempts ({write_attempts} files) — possible virus infection"
        )

    if malicious_hits or fork_count > _FORK_BOMB_THRESHOLD:
        verdict   = "MALICIOUS"
        score     = 0.95
        behaviors = malicious_hits[:]
        if fork_count > _FORK_BOMB_THRESHOLD:
            behaviors.append(f"Fork bomb detected ({fork_count} fork/clone calls)")
    elif exec_count > _EXEC_CHAIN_THRESHOLD or suspicious_hits:
        verdict   = "SUSPICIOUS"
        score     = 0.70 if exec_count > _EXEC_CHAIN_THRESHOLD else 0.55
        behaviors = suspicious_hits[:]
        if exec_count > _EXEC_CHAIN_THRESHOLD:
            behaviors.append(f"Dropper chain detected ({exec_count} execve calls)")
    else:
        verdict  = "CLEAN"
        score    = 0.0

    return {
        "verdict":        verdict,
        "sandbox_score":  score,
        "behaviors":      behaviors,
        "syscall_counts": syscall_counts,
    }
