"""Quét release exe-input, so SHA256 với docs/index.json, xuất matrix file cần dịch."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from common import REPO, download_asset, hash_file, log, run, set_output

INPUT_TAG = "exe-input"
OUTPUT_TAG = "decompiled"
INDEX = Path("docs/index.json")
DONE = ("done", "report_only")


def gh_json(path, paginate=False):
    cmd = ["gh", "api"] + (["--paginate", "--slurp"] if paginate else []) + [path]
    return json.loads(run(cmd))


def main():
    try:
        release = gh_json(f"repos/{REPO}/releases/tags/{INPUT_TAG}")
    except RuntimeError as e:
        log(f"::error::Chưa có release '{INPUT_TAG}' (hoặc không đọc được): {e}")
        sys.exit(1)
    pages = gh_json(f"repos/{REPO}/releases/{release['id']}/assets?per_page=100", True)
    assets = [a for page in pages for a in page]

    index = json.loads(INDEX.read_text("utf-8")) if INDEX.exists() else {"items": []}
    known = {i["sha256"]: i for i in index.get("items", [])}
    force = os.environ.get("FORCE", "").strip().lower()

    todo, seen = [], set()
    for a in assets:
        name = a["name"]
        if not name.lower().endswith(".exe"):
            continue
        digest = a.get("digest") or ""
        if digest.startswith("sha256:"):
            sha = digest[7:]
        else:
            tmp = Path(tempfile.mkdtemp()) / "f"
            download_asset(name, tmp)
            sha = hash_file(tmp)["sha256"]
            tmp.unlink()
        if sha in seen:
            log(f"Bỏ qua {name}: trùng nội dung với file đã xếp hàng")
            continue
        seen.add(sha)
        forced = bool(force) and (name.lower() == force or (len(force) >= 8 and sha.startswith(force)))
        if known.get(sha, {}).get("status") in DONE and not forced:
            log(f"Bỏ qua {name}: đã xử lý ({sha[:8]})")
            continue
        log(f"Cần xử lý: {name} ({sha[:8]})")
        todo.append({"name": name, "id": a["id"], "size": a["size"], "sha256": sha})

    if todo:
        r = subprocess.run(["gh", "release", "view", OUTPUT_TAG, "-R", REPO], capture_output=True)
        if r.returncode != 0:
            run(["gh", "release", "create", OUTPUT_TAG, "-R", REPO, "--title", "Kết quả dịch ngược",
                 "--notes", "Các file zip mã nguồn dịch ngược do workflow tạo ra."])
    set_output("matrix", json.dumps({"include": todo}))
    set_output("has_new", "true" if todo else "false")
    log(f"Tổng cộng {len(todo)} file cần xử lý.")


if __name__ == "__main__":
    main()
