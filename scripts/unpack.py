"""Gỡ protect gỡ được bằng tĩnh (UPX, de4dot) rồi chọn công cụ dịch ngược."""
import os
import shutil
from pathlib import Path

import detect
from common import WORK, run, set_output, step, version


@step
def main(st):
    prot = list(st["protectors"])
    target = Path(st["path"])
    st["unpacked"] = []

    if "UPX" in prot and shutil.which("upx"):
        out = WORK / "unpacked" / "sample_upx.exe"
        out.parent.mkdir(parents=True, exist_ok=True)
        try:
            run(["upx", "-d", "-q", "-o", out, target], timeout=1800)
            info = detect.inspect(out)
            target = out
            st["unpacked"].append("UPX")
            st["tools"].append("UPX " + version(["upx", "-V"]))
            st["info"], st["type"] = info, info["type"]
            prot = [p for p in prot if p != "UPX"] + [p for p in info["protectors"] if p not in prot and p != "UPX"]
        except Exception as e:
            st["warnings"].append(f"Không gỡ được UPX: {e}")

    de4dot = os.environ.get("DE4DOT")
    if st["type"] == "dotnet" and any(p in detect.DEOBF for p in prot) and de4dot and Path(de4dot).exists():
        out = WORK / "deobf" / "sample_clean.exe"
        out.parent.mkdir(parents=True, exist_ok=True)
        cmd = (["dotnet", de4dot] if de4dot.endswith(".dll") else [de4dot]) + ["-f", target, "-o", out]
        try:
            run(cmd, timeout=1800)
            if out.exists():
                target = out
                st["unpacked"].append("de4dot")
                st["tools"].append("de4dot-cex")
        except Exception as e:
            st["warnings"].append(f"de4dot không xử lý được: {e}")

    hard = [p for p in prot if p in detect.HARD]
    st.update(protectors=prot, hard_protectors=hard, target=str(target))
    tool = st["type"] if st["type"] in ("dotnet", "pyinstaller", "java", "native") else "none"
    if st["type"] == "unknown":
        st["status"], st["note"] = "report_only", "Không phải file PE hợp lệ nên không dịch ngược được."
    elif hard and st["type"] == "native":
        tool = "none"
        st["status"] = "report_only"
        st["note"] = f"Bị protect bằng {', '.join(hard)}: không thể dịch ngược bằng phân tích tĩnh."
    st["tool"] = tool
    set_output("tool", tool)


if __name__ == "__main__":
    main()
