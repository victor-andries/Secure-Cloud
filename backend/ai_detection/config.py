import os
import re

REDIS_HOST     = os.environ["REDIS_HOST"]
REDIS_PORT     = int(os.environ["REDIS_PORT"])
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or None

THRESHOLDS = {
    "CRITICAL": 0.85,
    "HIGH":     0.65,
    "MEDIUM":   0.45,
    "NORMAL":   0.0,
}

BEHAVIORAL_FEATURES = [
    "hour_of_day",
    "day_of_week",
    "is_night",
    "file_size_mb",
    "is_upload",
    "events_1h",
    "events_24h",
    "rapid_succession",
    "prev_anomaly_count",
    "ip_is_private",
    "events_per_hour",
    "high_volume",
]

N_FEATURES: int = 12

REDIS_FEAT_KEY  = "ai:feature_buffer"
BUFFER_MAXLEN   = 2000
MIN_FIT_SAMPLES = 50
REFIT_EVERY     = 100

_EICAR_PREFIX = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}"

_HIGH_RISK_RE = [
    re.compile(p, re.IGNORECASE) for p in [
        r"sub\s+auto(open|exec|close|new)\s*\(",
        r"sub\s+(document|workbook)_(open|close|new|activate)\s*\(",
        r"options\.virusprotection\s*=\s*false",
        r"application\.organizercopy",
        r"powershell[^\n]{0,30}-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}",
        r"iex\s*\(\s*\(?\s*new-object\s+net\.webclient\s*\)\.downloadstring",
        r"invoke-expression\s*\(\s*\(?\s*new-object",
        r"shell\s+[\"']?\s*cmd[\s/]",
        r"wscript\.shell.*\.run\s*\(",
        r"createobject\s*\(\s*[\"']wscript\.shell",
        r"curl\s+.+\|\s*(bash|sh|python|perl)",
        r"wget\s+.+\|\s*(bash|sh|python|perl)",
        r"wget\s+.+-O\s*-\s*\|\s*(bash|sh)",
        r"virtualalloc(ex)?\s*\(",
        r"createremotethread\s*\(",
        r"writeprocessmemory\s*\(",
        r"reg\s+add\s+.*(\\run\\|\\runonce\\)",
        r"hk(lm|cu)\\software\\microsoft\\windows\\currentversion\\run",
        r"schtasks\s+/create\s+.+/sc\s+(minute|hourly|daily|onlogon|onstart)",
    ]
]

_MEDIUM_RISK_RE = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){4,}",
        r"chr\([0-9]+\)\s*(&\s*chr\([0-9]+\)){3,}",
        r"string\.fromcharcode\s*\(\s*[0-9]+",
        r"base64[_\-\.]?(decode|encode)\s*\(",
        r"[A-Za-z0-9+/]{60,}={0,2}",
        r"eval\s*\(",
        r"exec\s*\(",
        r"shell_exec\s*\(",
        r"passthru\s*\(",
        r"system\s*\(\s*['\"]",
        r"os\.system\s*\(",
        r"subprocess\.(call|popen|run)\s*\(\s*['\"]",
        r"invoke-expression\b",
        r"invoke-command\b",
        r"\biex\b\s*[\(\$]",
        r"new-object\s+net\.webclient",
        r"invoke-webrequest\b",
        r"<\?php.{0,50}(eval|exec|system|passthru|shell_exec)\s*\(",
        r"runas\s+/user\s*:",
        r"\bsudo\s+-[si]\b",
        r"socket\.(connect|bind)\s*\(\s*[\(\"']",
        r"/dev/tcp/[0-9]{1,3}\.[0-9]{1,3}",
        r"nc\s+-[a-z]*e\s+",
        r"(clear-eventlog|wevtutil\s+cl)\b",
        r"vssadmin\s+delete\s+shadows",
        r"bcdedit\s+.+recoveryenabled\s+no",
        r"on\s+error\s+resume\s+next",
    ]
]

_PE_EXTENSIONS = {"exe", "dll", "sys", "scr", "com"}

_MACHO_MAGICS = {
    0xFEEDFACE: "macho32",
    0xCEFAEDFE: "macho32",
    0xFEEDFACF: "macho64",
    0xCFFAEDFE: "macho64",
    0xCAFEBABE: "fat",
}

_MACHO_DANGEROUS_STRINGS = [
    (b'/Library/LaunchAgents/',               0.20),
    (b'/Library/LaunchDaemons/',              0.20),
    (b'osascript',                             0.20),
    (b'applescript',                           0.20),
    (b'.kext',                                 0.20),
    (b'IOKit',                                 0.20),
    (b'task_for_pid',                          0.20),
    (b'/var/db/dslocal/nodes/Default/users/',  0.20),
]

_DOCUMENT_FORMATS = {
    "pdf",
    "jpg", "jpeg", "png", "gif", "webp",
    "mp4", "mp3", "avi", "mov", "mkv",
    "docx", "xlsx", "pptx", "odt",
}

_ARCHIVE_EXTENSIONS = {"zip", "tar", "gz", "bz2", "xz", "7z", "rar", "dmg", "pkg"}

_DANGEROUS_IN_ARCHIVE = {
    "exe", "dll", "sys", "scr", "com",
    "bat", "cmd", "ps1", "vbs", "js", "jse", "hta", "msi", "jar",
}

_SCANNABLE_IN_ARCHIVE = {
    "txt", "js", "jse", "ps1", "vbs", "bat", "cmd", "py", "sh",
    "html", "htm", "php", "asp", "aspx", "hta", "xml",
}
