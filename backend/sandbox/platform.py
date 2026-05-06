import struct

from .config import _RUNNERS, _ELF_MACHINE_QEMU

_MACHO_MAGICS = {
    0xFEEDFACE, 0xCEFAEDFE,
    0xFEEDFACF, 0xCFFAEDFE,
    0xCAFEBABE,
}


def _qemu_for_elf(file_bytes: bytes) -> str:
    """Return the qemu-user-static binary needed to run this ELF, or '' for native x86-64."""
    if len(file_bytes) < 20 or file_bytes[:4] != b'\x7fELF':
        return ""
    ei_data = file_bytes[5]  # 1=LE, 2=BE
    if ei_data == 1:
        e_machine = file_bytes[18] | (file_bytes[19] << 8)
    else:
        e_machine = (file_bytes[18] << 8) | file_bytes[19]
    if e_machine == 62:  # EM_X86_64 — native, no emulation needed
        return ""
    return _ELF_MACHINE_QEMU.get(e_machine, "")


def _detect_platform(data: bytes, filename: str) -> str:
    """
    Detect execution platform from magic bytes and filename.
    MZ header is checked before .com extension so 32-bit PE .com files
    are correctly routed to the Windows sandbox, not DOSBox.
    """
    if data[:4] == b'\x7fELF':
        return "elf"
    if data[:2] == b'MZ':
        return "windows"
    if len(data) >= 4:
        try:
            magic = struct.unpack('>I', data[:4])[0]
            if magic in _MACHO_MAGICS:
                return "macos"
        except struct.error:
            pass
    ext = filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''
    if ext == 'com' and len(data) >= 1 and data[0] in (0xEB, 0xE9):
        return "dos"
    if ext in _RUNNERS:
        return "script"
    return "unknown"
