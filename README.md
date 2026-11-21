# Dịch ngược .exe bằng GitHub Actions

Tải file `.exe` lên release, bấm chạy workflow, nhận về zip mã nguồn dịch ngược kèm `report.md`. Chỉ **phân tích tĩnh**, workflow không bao giờ chạy file của bạn.

## Cài đặt (một lần)

1. Đẩy repo này lên GitHub (public).
2. **Settings → Pages → Source: GitHub Actions**.
3. **Settings → Actions → General → Workflow permissions**: chọn *Read and write permissions*.
4. Tab **Actions → Cài đặt release → Run workflow** để tự tạo 2 release `exe-input` và `decompiled` (chạy lại không sao, release có rồi sẽ được giữ nguyên).

## Sử dụng

1. Vào release `exe-input` → Edit → kéo thả các file `.exe` vào → Update release.
2. Tab **Actions → Dịch ngược → Run workflow**. Để trống ô `force` là chỉ xử lý file mới.
3. Xem tiến trình ở tab Actions hoặc trên trang web (`https://<user>.github.io/<repo>/`), tải zip ở đó hoặc ở release `decompiled`.

Chống chạy lặp: so sánh theo **SHA256**, không theo tên file. File đã `done`/`report_only` thì bỏ qua, file `error` tự thử lại. Muốn dịch lại: nhập tên file hoặc ít nhất 8 ký tự đầu của SHA256 vào ô `force`.

## Kết quả

- Release `decompiled`: `<tên>-<hash8>.zip` gồm `source/` và `report.md`.
- `docs/index.json`: danh sách kết quả, trang web đọc file này.
- Workflow `pages.yml` không có bước build, chỉ upload `docs/` rồi deploy; `decompile.yml` gọi nó sau khi cập nhật `index.json` (commit của `GITHUB_TOKEN` không tự kích hoạt workflow khác).

## Công cụ theo loại file

| Loại | Công cụ |
|---|---|
| .NET | ILSpy (`ilspycmd`), de4dot-cex nếu có obfuscator |
| Python (PyInstaller) | pyinstxtractor-ng + pycdc |
| Java (jar đóng gói) | CFR |
| Native | Ghidra headless, xuất pseudo-C |
| Nhận diện | Detect It Easy (nếu cài được) + kiểm tra PE nội bộ |

## Giới hạn đã biết

- VMProtect, Themida, Enigma, Denuvo không gỡ được bằng phân tích tĩnh: file được ghi `report_only`, zip chỉ có `report.md`.
- Native chỉ ra pseudo-C, không phải mã gốc.
- .NET single-file bundle và exe Python không phải PyInstaller chưa được nhận diện riêng.
- Mỗi asset release tối đa 2 GB, mỗi job tối đa 6 giờ (đã đặt timeout 340 phút).
- Repo public thì ai cũng tải được `.exe` và kết quả. Chỉ dùng cho file bạn được phép phân tích.
- Chưa được chạy thử trên GitHub thật: các bước cài **Detect It Easy, de4dot, pyinstxtractor-ng, pycdc** dùng tên asset/gói chưa kiểm chứng và chưa pin phiên bản. Bước hỏng sẽ chỉ cảnh báo, workflow vẫn chạy tiếp.
