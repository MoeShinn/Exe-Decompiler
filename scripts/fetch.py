"""Tải file .exe từ release và tính hash."""
import os
import time

from common import WORK, download_asset, hash_file, step


@step
def main(st):
    st.update(name=os.environ["ASSET_NAME"], size=int(os.environ["ASSET_SIZE"]),
              sha256=os.environ["ASSET_SHA256"], started=time.time(),
              tools=[], warnings=[], status="running", note="")
    dest = WORK / "input" / "sample.exe"  # tên cố định, tránh ký tự lạ trong tên gốc
    download_asset(os.environ["ASSET_NAME"], dest)
    hashes = hash_file(dest)
    if hashes["sha256"] != st["sha256"]:
        raise RuntimeError("SHA256 sau khi tải không khớp với release")
    st.update(path=str(dest), hashes=hashes)


if __name__ == "__main__":
    main()
