# Thiết kế thuật toán DES và AES-128

Project học tập: tự cài đặt mã hóa và giải mã một khối dữ liệu, in các giá trị trung gian và đối chiếu test vector. Python 3.8+; không cần cài thư viện ngoài.

**Lưu ý:** đây là bản tham khảo để học và tự kiểm chứng. Các vector mặc định không được xác nhận là ví dụ trên bảng của giảng viên. Cần bổ sung chính xác các vector trên lớp trước khi nộp. Không dùng DES hoặc cài đặt minh họa này để bảo vệ dữ liệu thực tế. Chương trình không triển khai mode, IV hay padding.

## 1. Cấu trúc

```text
DES_AES128/
├── des.py                  # DES và lịch khóa
├── aes128.py               # AES-128 và mở rộng khóa
├── main.py                 # Chạy vector, lưu trace và kiểm chứng
├── vectors.json            # Test vector đầu vào và đáp án
├── tests/test_algorithms.py
├── results/                # Trace thực tế của từng vector + summary
├── README.md
└── .gitignore
```

## 2. Chạy bằng VS Code

1. Mở thư mục project bằng File > Open Folder.
2. Cài Python nếu máy chưa có, chọn Python interpreter trong VS Code.
3. Mở Terminal > New Terminal, chạy các lệnh bên dưới. Trên Linux có thể thay `python` bằng `python3`; Windows có thể dùng `py`.

```sh
python main.py
python -m unittest discover -s tests -v
```

Chạy riêng từng thuật toán hoặc chỉ xem tổng kết (trace vẫn được lưu đầy đủ):

```sh
python main.py --algorithm DES
python main.py --algorithm AES-128
python main.py --quiet
```

## 3. Thay test vector trên lớp

Mở `vectors.json`, bổ sung một object với `name` duy nhất, `algorithm` là `DES` hoặc `AES-128`, `key`, `plaintext`, `ciphertext` là chuỗi hex. DES cần 16 ký tự hex cho mỗi trường, AES-128 cần 32 ký tự. Ciphertext phải lấy từ đáp án trên bảng hoặc nguồn tham chiếu độc lập, không lấy kết quả chương trình làm đáp án.

Ví dụ cấu trúc (vector DES tham khảo):

```json
{"name":"des_lop_01", "algorithm":"DES", "key":"133457799BBCDFF1", "plaintext":"0123456789ABCDEF", "ciphertext":"85E813540F0AB405"}
```

Nếu có file vector riêng, dùng `python main.py --vectors vectors_lop.json --output results/lop`. Kiểm tra thủ công các trạng thái trung gian với ví dụ của thầy; thêm assertion vào `tests/test_algorithms.py` nếu có giá trị tham chiếu. Không ghi đè đáp án tham chiếu chỉ để chương trình báo PASS.

## 4. DES: các bước và hàm tương ứng

- `permute`: chọn bit theo bảng IP, FP, E, P, PC-1, PC-2. Bit số 1 là MSB.
- `key_schedule`: PC-1 bỏ 8 bit parity; chia C0/D0 28 bit; xoay trái theo lịch; PC-2 tạo 16 khóa con 48 bit.
- `feistel`: E mở rộng R từ 32 lên 48 bit, XOR khóa con, 8 S-box (mỗi hộp 6 → 4 bit), hoán vị P.
- `crypt`: IP, chia L0/R0, lặp L_i = R_(i-1), R_i = L_(i-1) XOR f(R_(i-1),K_i), ghép R16||L16 rồi FP. Giải mã đảo thứ tự khóa con.

Ví dụ DES vòng 1: IP = CC00CCFFF0AAF0AA, K1 = 1B02EFFC7072, E(R0) = 7A15557A1555, XOR = 6117BA866527, S-box = 5C82B597, P = 234AA9BB, L1 = F0AAF0AA, R1 = EF4A6544.

## 5. AES-128: các bước và hàm tương ứng

- `gf_mul`: phép nhân trong GF(2^8) theo đa thức 0x11B.
- `make_sbox`: tạo S-box bằng nghịch đảo nhân và biến đổi affine; sinh bảng nghịch đảo.
- `key_expansion`: tạo 44 word 32 bit (11 khóa vòng 128 bit) bằng RotWord, SubWord, Rcon và XOR.
- `add_round_key`: XOR state với khóa vòng.
- `sub_bytes`: thay thế từng byte theo S-box.
- `shift_rows`: hàng r dịch trái r byte.
- `mix_columns`: nhân mỗi cột với ma trận hệ số trong GF(2^8).
- `crypt`: AddRoundKey ban đầu; 9 vòng đầy đủ; vòng 10 bỏ MixColumns. Giải mã sử dụng các phép nghịch đảo và khóa vòng theo thứ tự ngược.

State được lưu theo cột: state[4*c+r] là phần tử hàng r, cột c. Ví dụ vector AES chính: AddRoundKey ban đầu = 00102030405060708090A0B0C0D0E0F0. Vòng 1: SubBytes = 63CAB7040953D051CD60E0E7BA70E18C; ShiftRows = 6353E08C0960E104CD70B751BACAD0E7; MixColumns = 5F72641557F5BC92F7BE3B291DB9F91A; AddRoundKey = 89D810E8855ACE682D1843D8CB128FE4.

## 6. Kết quả và kiểm thử

`results/summary.txt` chứa tổng kết vector. Mỗi file `results/<name>.txt` chứa lịch khóa, các phép biến đổi, giá trị từng vòng mã hóa và giải mã, so sánh đầu ra và PASS/FAIL. `results/unit_tests.txt` chứa kết quả unit test đã chạy.

Kiểm tra 4 vector tham khảo (2 DES, 2 AES-128); kiểm tra trạng thái vòng 1, các phép toán AES, độ dài đầu vào và 40 trường hợp round-trip với seed cố định. Round-trip không thay thế test vector độc lập.

## 7. Đưa lên GitHub

Tạo repository mới tên `DES-AES128` hoặc `AnToanThongTin-DES-AES128` (không dùng nickname làm tên repository). Không khởi tạo README từ GitHub nếu đã có project local. Trong terminal ở thư mục project:

```sh
git init
git add .
git commit -m "Implement DES and AES-128 with test vectors and traces"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/AnToanThongTin-DES-AES128.git
git push -u origin main
```

Thay `YOUR_USERNAME` bằng tài khoản thật và dùng URL repository GitHub đã tạo. Kiểm tra repository có chứa code, vectors, tests, results và README; cấp quyền xem cho giảng viên theo yêu cầu. Không đưa token, mật khẩu hay khóa bí mật thực tế lên GitHub. Link nộp là link repository của bạn.

## 8. Tự kiểm tra trước khi nộp

- Tự giải thích được cách chọn bit S-box DES, cách sinh K1, và tại sao đảo khóa con để giải mã.
- Tự giải thích được cách sắp xếp state AES, cách nhân GF và lý do vòng cuối không có MixColumns.
- Đối chiếu ít nhất một ví dụ trên bảng cho mỗi thuật toán, gồm các trạng thái giữa vòng.
- Chạy lại chương trình, cập nhật kết quả thật và ghi nhận những điểm khác biệt nếu có.

## Tài liệu tham khảo

- DES: FIPS 46-3 (đã rút lại, dùng cho mục đích học tập): https://csrc.nist.gov/pubs/fips/46-3/final
- DES ví dụ tính từng vòng: https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
- AES: FIPS 197, NIST (2023): https://csrc.nist.gov/pubs/fips/197/final
- AES ví dụ phụ lục B, C của bản FIPS 197 năm 2001: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
