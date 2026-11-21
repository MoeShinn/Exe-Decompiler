"""Dịch ngược theo loại file đã nhận diện."""
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from common import WORK, run, step, version

SRC = WORK / "source"


def dotnet(st, target):
    run(["ilspycmd", "-p", "-o", SRC, target], timeout=7200)
    st["tools"].append("ILSpy ilspycmd " + version(["ilspycmd", "--version"]))


def pyinstaller(st, target):
    work = WORK / "pyi"
    work.mkdir(parents=True, exist_ok=True)
    shutil.copy(target, work / "sample.exe")
    run(["pyinstxtractor-ng", "sample.exe"], cwd=work, timeout=1800)
    ext = work / "sample.exe_extracted"
    if not ext.exists():
        raise RuntimeError("pyinstxtractor không giải nén được file")
    pycdc = os.environ.get("PYCDC", "pycdc")
    stdlib = set(sys.stdlib_module_names)
    done = failed = 0
    for pyc in sorted(ext.rglob("*.pyc")):
        rel = pyc.relative_to(ext)
        parts = rel.parts
        module = parts[1] if parts[0].startswith("PYZ") and len(parts) > 1 else parts[0]
        if module.split(".")[0] in stdlib or module.startswith(("pyi", "struct")):
            continue
        if done + failed >= 3000:
            st["warnings"].append("Chỉ dịch ngược 3000 module đầu tiên.")
            break
        dest = (SRC / "python" / rel).with_suffix(".py")
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(dest, "wb") as f:
                p = subprocess.run([pycdc, str(pyc)], stdout=f, stderr=subprocess.PIPE, timeout=60)
            failed += p.returncode != 0
            done += p.returncode == 0
        except subprocess.TimeoutExpired:
            failed += 1
    if failed:
        st["warnings"].append(f"pycdc dịch chưa trọn vẹn {failed} module (có thể thiếu hoặc sai đoạn code).")
    st["tools"] += ["pyinstxtractor-ng", "pycdc"]


def java(st, target):
    jar, res = WORK / "app.jar", SRC / "resources"
    with zipfile.ZipFile(target) as z, zipfile.ZipFile(jar, "w", zipfile.ZIP_DEFLATED) as out:
        for item in z.infolist():
            if item.is_dir():
                continue
            data = z.read(item)
            if item.filename.endswith(".class"):
                out.writestr(item.filename, data)
                continue
            dest = (res / item.filename).resolve()
            if res.resolve() in dest.parents:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
    run(["java", "-jar", os.environ["CFR_JAR"], jar, "--outputdir", SRC / "java"], timeout=7200)
    st["tools"].append("CFR " + os.environ.get("CFR_VERSION", ""))


def native(st, target):
    headless = Path(os.environ["GHIDRA_HOME"]) / "support" / "analyzeHeadless"
    proj = WORK / "ghidra"
    proj.mkdir(parents=True, exist_ok=True)
    run([headless, proj, "proj", "-import", target,
         "-scriptPath", Path("scripts/ghidra").resolve(),
         "-postScript", "ExportC.java", SRC / "pseudo_c", "7200",
         "-deleteProject", "-analysisTimeoutPerFile", "9000"], timeout=18500)
    st["tools"].append("Ghidra " + os.environ.get("GHIDRA_VERSION", ""))


HANDLERS = {"dotnet": dotnet, "pyinstaller": pyinstaller, "java": java, "native": native}


@step
def main(st):
    tool = st.get("tool", "none")
    if tool == "none":
        return
    SRC.mkdir(parents=True, exist_ok=True)
    try:
        HANDLERS[tool](st, Path(st["target"]))
        count = sum(1 for p in SRC.rglob("*") if p.is_file())
        if count == 0:
            raise RuntimeError("Không sinh ra file mã nguồn nào")
        st["status"], st["source_files"] = "done", count
    except Exception as e:
        if not st.get("hard_protectors"):
            raise
        st["status"] = "report_only"
        st["note"] = f"Bị protect bằng {', '.join(st['hard_protectors'])}; dịch ngược thất bại ({e})"[:300]


if __name__ == "__main__":
    main()
