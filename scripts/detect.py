"""Nhận diện loại file, compiler và protector bằng phân tích tĩnh (không chạy file)."""
import json
import mmap
import re
import shutil
import zipfile
from datetime import datetime, timezone

import pefile

from common import run, set_output, step

MACHINES = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64"}
HARD = {"VMProtect", "Themida", "Enigma", "Denuvo"}  # không gỡ được bằng phân tích tĩnh
DEOBF = {"ConfuserEx", ".NET Reactor", "SmartAssembly", "Dotfuscator", "Babel", "Agile.NET"}
CANON = ["UPX", "VMProtect", "Themida", "Enigma", "ConfuserEx", ".NET Reactor", "SmartAssembly",
         "Dotfuscator", "Babel", "Agile.NET", "ASPack", "MPRESS", "PECompact", "Petite", "Denuvo"]
SECTION_SIGS = {
    "UPX": ("upx0", "upx1", "upx2"), "VMProtect": (".vmp0", ".vmp1", ".vmp2"),
    "Themida": (".themida", ".winlice"), "Enigma": (".enigma1", ".enigma2"),
    "ASPack": (".aspack", ".adata"), "MPRESS": (".mpress1", ".mpress2"),
    "PECompact": ("pec1", "pec2", "pecompact2"), "Petite": (".petite",),
}
STRING_SIGS = {
    "UPX": [b"UPX!"], "Themida": [b"Themida", b"WinLicense"], "VMProtect": [b"VMProtect"],
    "Enigma": [b"Enigma Protector"], "ConfuserEx": [b"ConfuserEx", b"Confused by"],
    ".NET Reactor": [b".NET Reactor", b"Eziriz"], "SmartAssembly": [b"SmartAssembly"],
    "Dotfuscator": [b"DotfuscatorAttribute"], "Babel": [b"BabelObfuscatorAttribute"],
    "Agile.NET": [b"CliSecureRttiAttribute", b"Agile.NET"], "Denuvo": [b"denuvo"],
}
COMPILERS = {
    "Go": [b"Go build ID", b"\xff Go buildinf:"], "Rust": [b"/rustc/", b"rust_begin_unwind"],
    "Delphi": [b"Embarcadero", b"Borland Delphi", b"SOFTWARE\\Borland"],
    "AutoIt": [b"AU3!", b"AutoIt v3"], "Nuitka": [b"Nuitka"], "MinGW/GCC": [b"GCC: ("],
}
INTERESTING = re.compile(
    r"https?://|ftp://|[A-Za-z]:\\|\\\\|HKEY_|SOFTWARE\\|\.(dll|exe|bat|ps1|cmd|vbs|json|xml|ini|db|sqlite)\b"
    r"|\b\d{1,3}(\.\d{1,3}){3}\b|[\w.+-]+@[\w-]+\.\w+|password|token|api[_-]?key|cmd\.exe|powershell", re.I)
STRING_SCAN_LIMIT = 128 * 1024 * 1024


def canon(name):
    for c in CANON:
        if c.lower() in name.lower():
            return c
    return name


def java_jar(path):
    try:
        with zipfile.ZipFile(path) as z:
            return any(n.endswith(".class") for n in z.namelist())
    except Exception:
        return False


def add(lst, item):
    if item and item not in lst:
        lst.append(item)


def inspect(path):
    info = {"is_pe": False, "type": "unknown", "compiler": "", "protectors": [], "sections": [],
            "imports": {}, "strings": [], "warnings": [], "high_entropy": []}
    try:
        pe = pefile.PE(str(path))
    except pefile.PEFormatError as e:
        info["warnings"].append(f"Không phải file PE hợp lệ: {e}")
        return info

    fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
    try:
        stamp = datetime.fromtimestamp(fh.TimeDateStamp, timezone.utc).isoformat(timespec="seconds")
    except (OverflowError, OSError, ValueError):
        stamp = ""
    info.update(is_pe=True, machine=MACHINES.get(fh.Machine, hex(fh.Machine)),
                format="PE32+" if oh.Magic == 0x20B else "PE32", is_dll=bool(fh.Characteristics & 0x2000),
                subsystem=pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, "?"), timestamp=stamp)
    dotnet = len(oh.DATA_DIRECTORY) > 14 and oh.DATA_DIRECTORY[14].VirtualAddress != 0

    prot = info["protectors"]
    for s in pe.sections:
        name = s.Name.rstrip(b"\0").decode("latin-1")
        ent = round(s.get_entropy(), 2) if s.SizeOfRawData < 64 * 1024 * 1024 else None
        info["sections"].append({"name": name, "vsize": s.Misc_VirtualSize, "rawsize": s.SizeOfRawData, "entropy": ent})
        if ent and ent > 7.2:
            info["high_entropy"].append(name)
        for pname, sigs in SECTION_SIGS.items():
            if name.lower() in sigs:
                add(prot, pname)
    for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = e.dll.decode("latin-1")
        info["imports"][dll] = [i.name.decode("latin-1") if i.name else f"ord{i.ordinal}" for i in e.imports][:200]
    pe.close()

    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        def has(*needles):
            return any(mm.find(n) != -1 for n in needles)

        for pname, needles in STRING_SIGS.items():
            if has(*needles):
                add(prot, pname)
        if dotnet:
            m = re.search(rb"\.NET(?:Framework|CoreApp|Standard),Version=v[\d.]+", mm)
            info["type"], info["compiler"] = "dotnet", ".NET " + (m.group().decode() if m else "")
        elif has(b"MEI\x0c\x0b\x0a\x0b\x0e"):
            info["type"], info["compiler"] = "pyinstaller", "Python (PyInstaller)"
        elif java_jar(path):
            info["type"], info["compiler"] = "java", "Java"
        else:
            info["type"] = "native"
            info["compiler"] = next((c for c, n in COMPILERS.items() if has(*n)), "")
            if not info["compiler"] and any(d.upper().startswith(("VCRUNTIME", "MSVCP")) for d in info["imports"]):
                info["compiler"] = "MSVC (C/C++)"
            if any(d.lower().startswith("python") for d in info["imports"]):
                info["warnings"].append("Có dấu hiệu Python nhưng không phải PyInstaller (py2exe/cx_Freeze/Nuitka?).")
        seen = set()
        for m in re.compile(rb"[\x20-\x7e]{6,}").finditer(mm, 0, min(len(mm), STRING_SCAN_LIMIT)):
            s = m.group().decode("ascii")[:200]
            if s not in seen and INTERESTING.search(s):
                seen.add(s)
                info["strings"].append(s)
                if len(seen) >= 150:
                    break
    return info


def run_diec(path):
    """Trả về (danh sách mô tả, tên packer/protector) từ Detect It Easy nếu có."""
    if not shutil.which("diec"):
        return [], []
    try:
        data = json.loads(run(["diec", "--json", path], check=False, timeout=300))
        lines, names = [], []
        for d in data.get("detects", []):
            for v in d.get("values", []):
                lines.append(v.get("string", ""))
                if v.get("type") in ("Packer", "Protector", "Obfuscator", "Cryptor"):
                    names.append(canon(v.get("name", "")))
        return lines, names
    except Exception:
        return [], []


@step
def main(st):
    info = inspect(st["path"])
    diec_lines, names = run_diec(st["path"])
    for n in names:
        add(info["protectors"], n)
    info["diec"] = diec_lines
    if diec_lines:
        st["tools"].append("Detect It Easy (diec)")
    if info["high_entropy"] and not info["protectors"]:
        info["warnings"].append("Có section entropy cao, file có thể đã bị pack bằng công cụ không nhận diện được.")
    st.update(info=info, type=info["type"], protectors=info["protectors"])
    set_output("type", info["type"])
    set_output("upx", "true" if "UPX" in info["protectors"] else "false")


if __name__ == "__main__":
    main()
