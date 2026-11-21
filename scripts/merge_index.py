"""Gộp các result-*.json vào docs/index.json (mục cũ cùng SHA256 bị thay thế)."""
import json
from datetime import datetime, timezone
from pathlib import Path

from common import log

INDEX = Path("docs/index.json")


def main():
    results = sorted(Path("artifacts").rglob("result-*.json"))
    if not results:
        log("Không có kết quả nào để gộp.")
        return
    data = json.loads(INDEX.read_text("utf-8")) if INDEX.exists() else {}
    by_hash = {i["sha256"]: i for i in data.get("items", [])}
    for f in results:
        item = json.loads(f.read_text("utf-8"))
        by_hash[item["sha256"]] = item
    items = sorted(by_hash.values(), key=lambda i: i.get("processed_at", ""), reverse=True)
    out = {"updated": datetime.now(timezone.utc).isoformat(timespec="seconds"), "items": items}
    INDEX.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n", "utf-8")
    log(f"Đã gộp {len(results)} kết quả, index có {len(items)} mục.")


if __name__ == "__main__":
    main()
