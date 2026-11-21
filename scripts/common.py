"""Tiện ích dùng chung cho các script phân tích tĩnh."""
import hashlib
import json
import os
import subprocess
import traceback
from pathlib import Path

WORK = Path(os.environ.get("WORK_DIR", "work"))
STATE_FILE = WORK / "state.json"
REPO = os.environ.get("GITHUB_REPOSITORY", "")


def log(msg):
    print(msg, flush=True)


def run(cmd, cwd=None, timeout=None, check=True, stdout=None):
    """Chạy lệnh, trả về stdout. Ném RuntimeError kèm đuôi log nếu lỗi."""
    cmd = [str(c) for c in cmd]
    log("$ " + " ".join(cmd))
    p = subprocess.run(cmd, cwd=cwd, timeout=timeout, text=True, errors="replace",
                       stdout=stdout or subprocess.PIPE, stderr=subprocess.PIPE)
    if check and p.returncode != 0:
        tail = (p.stderr or "").strip()[-500:] or (p.stdout or "").strip()[-500:]
        raise RuntimeError(f"{Path(cmd[0]).name} lỗi (mã {p.returncode}): {tail}")
    return p.stdout or ""


def version(cmd):
    try:
        out = run(cmd, check=False).strip().splitlines()
        return out[0] if out else "?"
    except Exception:
        return "?"


def hash_file(path):
    algos = {k: hashlib.new(k) for k in ("md5", "sha1", "sha256")}
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            for h in algos.values():
                h.update(chunk)
    return {k: h.hexdigest() for k, h in algos.items()}


def download_asset(asset_id, dest):
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "wb") as f:
        run(["gh", "api", "-H", "Accept: application/octet-stream",
             f"repos/{REPO}/releases/assets/{asset_id}"], stdout=f)


def load_state():
    return json.loads(STATE_FILE.read_text("utf-8")) if STATE_FILE.exists() else {}


def save_state(st):
    WORK.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(st, ensure_ascii=False, indent=1), "utf-8")


def set_output(key, value):
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"{key}={value}\n")


def step(fn):
    """Bọc một bước: lỗi thì ghi vào state (status=error) thay vì làm hỏng job."""
    def wrapper():
        st = load_state()
        if st.get("status") == "error":
            log("Bỏ qua: bước trước đã lỗi")
            return
        try:
            fn(st)
        except Exception as e:
            traceback.print_exc()
            where = Path(fn.__code__.co_filename).stem
            st["status"] = "error"
            st["note"] = f"{where}: {e}"[:300]
            log("::error::" + st["note"].replace("\n", " "))
        save_state(st)
    return wrapper
