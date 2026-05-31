import os

SANDBOX_BASE_IMAGE = os.getenv("SANDBOX_BASE_IMAGE", "")
SANDBOX_DOS_IMAGE  = os.getenv("SANDBOX_DOS_IMAGE",  "")
SANDBOX_WINE_IMAGE = os.getenv("SANDBOX_WINE_IMAGE", "")

_MAX_SANDBOX_FILE = 50 * 1024 * 1024

_RUNNERS = {
    "sh":   ["bash"],
    "bash": ["bash"],
    "zsh":  ["bash"],
    "py":   ["python3"],
    "pl":   ["perl"],
}

_ELF_MACHINE_QEMU: dict[int, str] = {
    3:   "qemu-i386-static",
    40:  "qemu-arm-static -L /usr/arm-linux-gnueabihf",
    183: "qemu-aarch64-static -L /usr/aarch64-linux-gnu",
    8:   "qemu-mips-static",
    20:  "qemu-ppc-static",
    21:  "qemu-ppc64-static",
}
