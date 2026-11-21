"""Sinh report.md (lệnh 'report'), đóng gói + tải lên release + ghi result-<hash8>.json (lệnh 'package')."""
import json
import os
import re
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from common import REPO, WORK, load_state, log, run, save_state

SRC = WORK / "source"
REPORT = WORK / "report.md"
STATUS_VI = {"done": "Đã dịch ngược", "report_only": "Chỉ có báo cáo", "error": "Lỗi"}
LIMITS = {
    "native": "Kết quả là pseudo-C do Ghidra sinh ra, không phải mã gốc: tên biến, kiểu dữ liệu và cấu trúc "
              "phần lớn đã mất, thường không biên dịch lại được.",
    "dotnet": "Gần với mã gốc nhưng comment đã mất; nếu bị obfuscate thì tên lớp/hàm có thể khó đọc.",
    "pyinstaller": "Mã Python dịch ngược bằng pycdc có thể thiếu hoặc sai ở một số đoạn; thư viện chuẩn đã được bỏ qua.",
    "java": "CFR dịch ngược khá tốt nhưng tên cục bộ và comment đã mất.",
}


def fmt_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def table(headers, rows):
    esc = lambda c: str(c).replace("|", "\\|")
    return ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)] + \
           ["| " + " | ".join(esc(c) for c in r) + " |" for r in rows]


def run_url():
    rid = os.environ.get("GITHUB_RUN_ID")
    return f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{REPO}/actions/runs/{rid}" if rid else ""


def build_report(st):
    info, hashes, status = st.get("info", {}), st.get("hashes", {}), st.get("status", "error")
    prot = st.get("protectors", [])
    L = [f"# Báo cáo dịch ngược: {st.get('name', '?')}", "", f"- **Trạng thái:** {STATUS_VI.get(status, status)}"]
    if st.get("note"):
        L.append(f"- **Ghi chú:** {st['note']}")
    L += ["", "## Thông tin file", ""] + table(["Mục", "Giá trị"], [
        ("Tên", st.get("name", "?")), ("Kích thước", fmt_size(st.get("size", 0))),
        ("MD5", hashes.get("md5", "")), ("SHA1", hashes.get("sha1", "")), ("SHA256", st.get("sha256", "")),
        ("Kiến trúc", info.get("machine", "")), ("Định dạng", info.get("format", "")),
        ("Subsystem", info.get("subsystem", "")), ("DLL", "có" if info.get("is_dll") else "không"),
        ("Thời điểm biên dịch (theo header)", info.get("timestamp", ""))])
    L += ["", "## Nhận diện", ""] + table(["Mục", "Giá trị"], [
        ("Loại", st.get("type", "unknown")), ("Compiler/runtime", info.get("compiler", "") or "không rõ"),
        ("Protector nhận diện", ", ".join(prot) or "không"), ("Đã gỡ", ", ".join(st.get("unpacked", [])) or "không"),
        ("Không gỡ được tĩnh", ", ".join(st.get("hard_protectors", [])) or "không")])
    if info.get("diec"):
        L += ["", "Kết quả Detect It Easy:", ""] + [f"- {x}" for x in info["diec"] if x]
    L += ["", "## Công cụ", ""] + [f"- {t}" for t in st.get("tools", [])]
    notes = [LIMITS[st["type"]]] if st.get("type") in LIMITS and status == "done" else []
    notes += st.get("warnings", []) + info.get("warnings", [])
    if notes:
        L += ["", "## Cảnh báo và giới hạn", ""] + [f"- {n}" for n in notes]
    if info.get("sections"):
        L += ["", "## Section", ""] + table(["Tên", "Virtual size", "Raw size", "Entropy"], [
            (s["name"], s["vsize"], s["rawsize"], "" if s["entropy"] is None else s["entropy"]) for s in info["sections"]])
    if info.get("imports"):
        L += ["", "## Import", ""]
        for dll, funcs in list(info["imports"].items())[:40]:
            more = f", … (+{len(funcs) - 25})" if len(funcs) > 25 else ""
            L.append(f"- **{dll}**: {', '.join(funcs[:25])}{more}")
    if info.get("strings"):
        L += ["", "## Chuỗi đáng chú ý", "", "```"] + info["strings"] + ["```"]
    files = sorted(p for p in SRC.rglob("*") if p.is_file()) if SRC.exists() else []
    if files:
        L += ["", "## Cấu trúc source", "", "```"]
        L += [f"{p.relative_to(SRC).as_posix()}  ({fmt_size(p.stat().st_size)})" for p in files[:200]]
        if len(files) > 200:
            L.append(f"… và {len(files) - 200} file nữa")
        L.append("```")
    took = time.time() - st["started"] if st.get("started") else 0
    L += ["", "## Thời gian", "", f"- Tổng thời gian xử lý: {took / 60:.1f} phút"]
    if run_url():
        L.append(f"- Lần chạy workflow: {run_url()}")
    return "\n".join(L) + "\n"


def report():
    st = load_state()
    WORK.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(build_report(st), "utf-8")
    log("Đã sinh report.md")


def package():
    st = load_state()
    sha = st.get("sha256") or os.environ.get("ASSET_SHA256", "")
    name = st.get("name") or os.environ.get("ASSET_NAME", "file.exe")
    status = st.get("status", "error")
    note = st.get("note", "")
    if status == "running":
        status, note = "error", "Quá trình xử lý bị gián đoạn."
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(name).stem).strip("._") or "file"
    zip_name, zip_url = f"{stem}-{sha[:8]}.zip", ""
    if status in ("done", "report_only") and REPORT.exists():
        try:
            zp = WORK / zip_name
            with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
                z.write(REPORT, "report.md")
                if status == "done":
                    for f in sorted(SRC.rglob("*")):
                        if f.is_file():
                            z.write(f, "source/" + f.relative_to(SRC).as_posix())
            run(["gh", "release", "upload", "decompiled", zp, "--clobber", "-R", REPO], timeout=3600)
            zip_url = f"https://github.com/{REPO}/releases/download/decompiled/{quote(zip_name)}"
        except Exception as e:
            status, note = "error", f"Đóng gói/tải lên thất bại: {e}"[:300]
            log("::error::" + note.replace("\n", " "))
    item = {
        "sha256": sha, "name": name, "size": st.get("size", 0), "type": st.get("type", "unknown"),
        "protector": ", ".join(st.get("protectors", [])) or "none", "status": status,
        "zip": zip_name if zip_url else "", "zip_url": zip_url,
        "processed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "run_url": run_url(), "note": note,
    }
    (WORK / f"result-{sha[:8]}.json").write_text(json.dumps(item, ensure_ascii=False, indent=2), "utf-8")
    st["status"] = status
    save_state(st)
    log(f"Kết quả: {name} -> {status}")


if __name__ == "__main__":
    {"report": report, "package": package}[sys.argv[1]]()
