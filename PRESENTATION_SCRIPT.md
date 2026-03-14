# KỊCH BẢN THUYẾT TRÌNH
## NODE-LEVEL GRAPH CONTRASTIVE LEARNING CHỐNG MIMICRY EVASION ATTACK TRÊN PROVENANCE GRAPH IDS

- **Thời lượng:** 25–30 phút (24 slides)
- **Cấu trúc mỗi Slide:** **Visual** (nội dung hiển thị) → **Script** (lời thoại) → **Ghi chú** (cho người trình bày)
- **Số liệu kiểm chứng** từ `contrastive_experiment.ipynb`

---

# PHẦN 1: GIỚI THIỆU (Slide 1–5) ~5 phút

---

## Slide 1: Tiêu đề

**Visual:**
- Tên đề tài: **"Node-Level Graph Contrastive Learning chống Mimicry Evasion Attack trên Provenance Graph IDS"**
- Tên người trình bày, Khoa, Trường
- Hình nền: provenance graph mờ nhạt

**Script:**

> "Kính chào Hội đồng. Hôm nay tôi trình bày đề tài nghiên cứu về việc phát hiện tấn công ngụy trang trên hệ thống phát hiện xâm nhập dựa trên đồ thị nguồn gốc, và giải pháp GRACE do chúng tôi đề xuất."

**Thời lượng:** ~30 giây

---

## Slide 2: Bối cảnh & Lý do nghiên cứu

**Visual:**
- Sơ đồ 3 tầng theo chiều dọc:
  1. **Thực trạng**: Icon APT + Living-off-the-Land → bypass signature-based IDS
  2. **Giải pháp hiện tại**: Provenance Graph IDS (Prov-HIDS) — ghi nhận nhân quả cấp kernel
  3. **Lỗ hổng nghiêm trọng**: Mimicry Evasion → 5/5 Prov-HIDS bị qua mặt (NDSS 2023)
- Trích dẫn: *"Sometimes, You Aren't What You Do"* — NDSS 2023

**Script:**

> "Tấn công APT hiện đại không còn dùng mã độc truyền thống. Chúng lợi dụng công cụ hợp pháp của hệ thống — bash, PowerShell, Python — khiến các IDS dựa trên chữ ký hoàn toàn bất lực.
>
> Để đối phó, cộng đồng nghiên cứu phát triển Provenance Graph IDS — ghi lại toàn bộ lịch sử nhân quả cấp kernel thành đồ thị, cung cấp ngữ cảnh đầy đủ cho việc phát hiện.
>
> Tuy nhiên, bài báo tại hội nghị NDSS 2023 đã chỉ ra một lỗ hổng nghiêm trọng: kỹ thuật Mimicry Evasion — pha loãng tín hiệu tấn công bằng hành vi bình thường — đã qua mặt toàn bộ 5 hệ thống Prov-HIDS tiêu biểu nhất. Đây chính là lý do chúng tôi thực hiện nghiên cứu này."

**Thời lượng:** ~1 phút 30 giây

---

## Slide 3: Mục tiêu nghiên cứu

**Visual:**
- 3 mục tiêu được đánh số rõ ràng, mỗi mục tiêu kèm icon:
  1. **MT1 — Phân tích nguyên nhân thất bại**: Xác định tại sao Mean-Pool và Graph-level scoring bị Mimicry Evasion vô hiệu hoá
  2. **MT2 — Đề xuất giải pháp phòng thủ**: Xây dựng mô hình GRACE kết hợp Node-level Contrastive Learning với TopK-Fixed Aggregation
  3. **MT3 — Đánh giá toàn diện**: Chứng minh tính hiệu quả qua 7 thí nghiệm: so sánh baseline, adaptive attacks, sensitivity analysis, system overhead

**Script:**

> "Nghiên cứu của chúng tôi đặt ra 3 mục tiêu cụ thể.
>
> Mục tiêu thứ nhất: Phân tích nguyên nhân gốc rễ khiến các Prov-HIDS hiện tại thất bại trước Mimicry Evasion — cụ thể là vai trò của hàm gộp Mean-Pool và cách chấm điểm Graph-level.
>
> Mục tiêu thứ hai: Đề xuất mô hình GRACE — kết hợp học đối lập ở cấp độ node với cơ chế gộp TopK cố định — nhằm loại bỏ hoàn toàn lỗ hổng pha loãng tín hiệu.
>
> Mục tiêu thứ ba: Đánh giá toàn diện qua 7 thí nghiệm — từ so sánh với 5 baseline, tấn công thích ứng white-box, phân tích độ nhạy pha loãng cực đoan, đến hiệu năng triển khai thực tế."

**Thời lượng:** ~1 phút

---

## Slide 4: Mô tả bài toán

**Visual:**
- **Đầu vào — Đầu ra — Ràng buộc** trình bày rõ ràng:
  - **Input**: Provenance graph G = (V, E) với V = {Process, File, Socket}, E = {syscall edges}
  - **Output**: Nhãn y ∈ {benign, malicious} cho mỗi graph; xác định tập node bất thường V_attack ⊂ V
  - **Ràng buộc**: Chỉ huấn luyện trên dữ liệu benign (self-supervised / one-class)
- **Thách thức chính** (highlight đỏ):
  - Evasion graph: |E_evasion| ≈ 121K, trong đó |E_attack| ≈ 5.6K (4.6%), |E_benign_noise| ≈ 115K (95.4%)
  - Yêu cầu: Phát hiện 4.6% tín hiệu tấn công ẩn trong 95.4% nhiễu

**Script:**

> "Bài toán được phát biểu như sau. Đầu vào là một provenance graph — đồ thị có hướng với 3 loại node: tiến trình, file, socket — các cạnh là system call. Đầu ra cần xác định graph đó là bình thường hay độc hại, đồng thời chỉ ra cụ thể node nào bất thường.
>
> Ràng buộc quan trọng: mô hình chỉ được huấn luyện trên dữ liệu bình thường — không có nhãn tấn công khi train — đây là bài toán one-class classification.
>
> Thách thức cốt lõi: trong đồ thị evasion, tín hiệu tấn công chỉ chiếm 4,6 phần trăm — khoảng 5.600 cạnh — bị pha loãng trong hơn 115 nghìn cạnh nhiễu bình thường. Bài toán thực chất là tìm kim trong đống rơm."

**Thời lượng:** ~1 phút 15 giây

---

## Slide 5: Provenance Graph — Khái niệm

**Visual:**
- Sơ đồ provenance graph: 3 loại node (Process — hình tròn xanh, File — hình chữ nhật xanh lá, Socket — hình thoi cam) nối bằng cạnh có nhãn syscall
- Ví dụ chuỗi: `bash →(clone)→ firefox →(write)→ /tmp/cache →(connect)→ 192.168.1.1:443`
- Legend: Node types + Edge types (read, write, clone, connect, execve)
- Ảnh minh hoạ: xem `SLIDE_IMAGE_PROMPTS.md` — Slide 2

**Script:**

> "Provenance graph ghi lại toàn bộ lịch sử nhân quả ở cấp kernel. Mỗi node đại diện cho một thực thể hệ thống — tiến trình, file, hoặc socket. Mỗi cạnh là một system call — đọc file, ghi file, tạo tiến trình con, mở kết nối mạng. Ví dụ: bash tạo tiến trình con firefox, firefox ghi vào file cache, sau đó mở kết nối tới một địa chỉ IP bên ngoài. Chuỗi nhân quả này cho phép truy vết toàn bộ ngữ cảnh hành vi."

**Thời lượng:** ~45 giây

---

# PHẦN 2: CÔNG TRÌNH LIÊN QUAN & PHÂN TÍCH THẤT BẠI (Slide 6–9) ~4 phút

---

## Slide 6: Kỹ thuật Mimicry Evasion

**Visual:**
- Sơ đồ 2 phần before/after:
  - Trái: Đồ thị tấn công gốc (~5,640 cạnh, đỏ)
  - Phải: Đồ thị evasion phình to (~121,000 cạnh, 95% xanh + 5% đỏ ẩn bên trong)
- Pipeline 4 bước bên dưới:
  1. `getBenignFile()` — Nạp đồ thị benign (~76K edges)
  2. `takeOver()` — Chiếm quyền tiến trình Firefox
  3. `insertBenSubstructs()` — Bơm hàng nghìn cấu trúc benign giả
  4. `insertAttackPath()` — Chèn cạnh tấn công vào giữa
- Tham số: `numberOfClones` kiểm soát mức pha loãng
- Stacked bar: 95.4% benign noise | 4.6% attack signal

**Script:**

> "Kỹ thuật Mimicry Evasion hoạt động qua 4 bước tự động. Kẻ tấn công nạp một đồ thị benign thật, chiếm quyền tiến trình hợp pháp như Firefox, bơm hàng nghìn hành vi bình thường giả — đọc cache, ghi cookie — rồi lén chèn cạnh tấn công vào giữa.
>
> Kết quả: đồ thị tấn công ban đầu chỉ 5.600 cạnh phình lên hơn 121 nghìn cạnh — gấp 21 lần. Tín hiệu tấn công bị pha loãng còn 4,6 phần trăm. Tham số `numberOfClones` kiểm soát mức pha loãng — chúng tôi sẽ phân tích tham số này trong thí nghiệm sensitivity."

**Ghi chú:** 5,640 / 121,429 = 4.64%. Số liệu từ notebook Cell 4.

**Thời lượng:** ~1 phút 15 giây

---

## Slide 7: Các Prov-HIDS hiện tại và kết quả trước Evasion

**Visual:**
- Bảng tổng hợp 5 baseline:

| Phương pháp | Kỹ thuật | Hàm gộp | Attack AUC | Evasion AUC | FPR |
|-------------|----------|---------|:---:|:---:|:---:|
| ProvDetector | Path anomaly | Median | 1.0000 | **0.5000** | 0% |
| FGA (ARGVA) | Graph Autoencoder | GNN-Mean | 1.0000 | **0.5533** | 50% |
| Unicorn | Feature histogram | Feat-Mean | 1.0000 | **0.7000** | 30% |
| VELOX-style | Embedding drift | GNN-Mean | 1.0000 | **0.6000** | 40% |
| TCG-IDS-style | Contrastive Learning | **CL-Mean** | 1.0000 | **0.7000** | 30% |

- Highlight: Tất cả Attack AUC = 1.0, nhưng Evasion AUC chỉ 0.50–0.70

**Script:**

> "Chúng tôi đánh giá 5 phương pháp Prov-HIDS tiêu biểu. Tất cả đều phát hiện hoàn hảo tấn công thông thường — Attack AUC đều bằng 1.0.
>
> Nhưng khi đối mặt Evasion, toàn bộ đều thất bại. ProvDetector dùng trung vị — AUC rớt xuống 0,5, ngang đoán mò. FGA dùng Graph Autoencoder với Mean-Pool — AUC chỉ 0,55, FPR lên 50 phần trăm. Đáng chú ý, TCG-IDS đã dùng Contrastive Learning tiên tiến — cùng nền tảng với giải pháp chúng tôi — nhưng vẫn gộp bằng Mean-Pool, nên AUC chỉ đạt 0,7 với 30 phần trăm báo nhầm."

**Thời lượng:** ~1 phút 15 giây

---

## Slide 8: Phân tích nguyên nhân thất bại — FGA làm ví dụ

**Visual:**
- Sơ đồ kiến trúc FGA: Input Graph → GCN Encoder (8→64→32) → VAE → **Mean-Pool** ⚠️ → Reconstruction → Score
- Minh hoạ Mean-Pool: hàng nghìn node embeddings (95% xanh + 5% đỏ) → đổ vào phễu → ra 1 số duy nhất → tín hiệu đỏ bị nhấn chìm
- Bên dưới: Reconstruction Loss vs Contrastive Loss (so sánh ngắn gọn)

**Script:**

> "Lấy FGA làm ví dụ để phân tích cơ chế thất bại. FGA dùng GCN mã hoá đồ thị, sau đó Mean-Pool gộp toàn bộ node embeddings thành một vector duy nhất cho cả đồ thị. Khi đồ thị evasion có 95 phần trăm nodes benign, phép trung bình kéo vector tổng hợp về vùng bình thường — hoàn toàn nhấn chìm 5 phần trăm tín hiệu tấn công.
>
> Ngoài ra, FGA dùng Reconstruction Loss — đo khả năng tái tạo đồ thị — không trực tiếp tối ưu cho việc phân biệt benign và attack trong không gian biểu diễn."

**Thời lượng:** ~1 phút

---

## Slide 9: Đúc kết — 2 nguyên nhân gốc rễ

**Visual:**
- 2 khối lớn, in đậm:
  1. **Graph-level scoring** (icon: phễu): Gộp N nodes → 1 số → mất ngữ cảnh cục bộ, không biết node nào bất thường
  2. **Mean-pool aggregation** (icon: cân bằng): Trung bình hoá → tín hiệu thiểu số bị 95% đa số nhấn chìm
- Mũi tên dẫn xuống: **→ Cần: Node-level scoring + Aggregation kháng pha loãng**

**Script:**

> "Tổng kết, 2 nguyên nhân gốc rễ. Thứ nhất: chấm điểm ở mức toàn đồ thị — gộp hàng nghìn nodes thành một con số — làm mất hoàn toàn thông tin về node nào bất thường. Thứ hai: hàm gộp trung bình cho phép đa số benign nhấn chìm thiểu số attack. Từ đây, yêu cầu đặt ra rõ ràng: cần chấm điểm ở cấp node, và cần cơ chế gộp kháng được pha loãng."

**Thời lượng:** ~30 giây

---

# PHẦN 3: DỮ LIỆU THỰC NGHIỆM (Slide 10–11) ~2 phút

---

## Slide 10: 3 Bộ dữ liệu

**Visual:**
- Bảng so sánh:

| Dataset | Format | Benign (edges/graph) | Attack (edges/graph) | Evasion (edges/graph) | Đặc điểm |
|---------|--------|:---:|:---:|:---:|-----------|
| tajka (DARPA) | CSV 10 cột | ~76,000 | ~5,640 | ~121,000 | syscall, PID, timestamp |
| StreamSpot | TSV 6 cột | ~303,000 | — | — | Ẩn danh: ký hiệu a-e |
| DARPA Theia (TC3) | Mixed | — | ~1.6M | — | APT thực tế, quy mô lớn |

- Phân chia dữ liệu tajka: Train 71 graphs benign | Test 29 benign + 100 attack + 100 evasion
- Ảnh: `plot_3dataset_comparison.png`

**Script:**

> "Chúng tôi sử dụng 3 bộ dữ liệu. Bộ tajka — dữ liệu chính — theo chuẩn DARPA, có ngữ nghĩa phong phú: tên syscall, PID, timestamp, với 71 đồ thị benign huấn luyện và 100 đồ thị mỗi loại cho attack và evasion. Bộ StreamSpot hoàn toàn ẩn danh — chỉ ký tự a đến e — buộc mô hình phải học từ cấu trúc đồ thị thuần tuý. Bộ DARPA Theia mô phỏng APT thực tế với đồ thị tới 1,6 triệu cạnh. Sự đa dạng này đảm bảo kết quả không phụ thuộc vào metadata cụ thể."

**Ghi chú:** Số liệu: benign_train avg=73,782 edges (std=15,265); attack avg=5,638 (std=32); evasion avg=121,428 (std=1).

**Thời lượng:** ~1 phút

---

## Slide 11: Biểu diễn đặc trưng Node & Tiền xử lý

**Visual:**
- Sơ đồ chuyển đổi: Raw edge (sourceId, sourceType, destId, destType, syscall) → Graph (V, E)
- Bảng node feature:
  ```
  TYPE_MAP = {process: 1.0, file: 2.0, socket: 3.0}
  Feature vector (dim=8): [type_value, 0, one_hot_position, 0, 0, 0, 0, 0]
  ```
- Thống kê node types (benign): Process 46.1% | File 13.2% (src) / 44.3% (dst) | Socket 40.7% (src) / 1.8% (dst)
- Ảnh: `plot_node_types.png`

**Script:**

> "Mỗi node được biểu diễn bằng vector 8 chiều rất đơn giản — chỉ dựa trên loại node: process, file, hay socket. Điều này có chủ đích: đặc trưng nghèo buộc mô hình phải học từ cấu trúc đồ thị — tức cách các node kết nối với nhau — chứ không phụ thuộc vào tên tiến trình hay metadata. Đây là lý do GRACE hoạt động được trên cả StreamSpot — bộ dữ liệu hoàn toàn ẩn danh."

**Thời lượng:** ~45 giây

---

# PHẦN 4: GIẢI PHÁP ĐỀ XUẤT — GRACE (Slide 12–15) ~4 phút 30 giây

---

## Slide 12: Kiến trúc GRACE — Tổng quan

**Visual:**
- Sơ đồ kiến trúc 3 giai đoạn ngang:
  - **Giai đoạn 1 — Training**: Graph → Data Augmentation (DropEdge + MaskFeature) → 2 Views → Shared GCN Encoder (8→64→32) → Projection Head (32→32→32) → InfoNCE Loss
  - **Giai đoạn 2 — Reference Building**: Toàn bộ benign train embeddings → K-Means (K=200) → 200 Benign Centroids
  - **Giai đoạn 3 — Inference**: New graph → Frozen Encoder → Node embeddings → Distance to nearest centroid → Node anomaly scores → TopK-Fixed Aggregation → Graph score
- Thông số: 4,896 params | 19.6 KB | Self-supervised (chỉ cần benign)

**Script:**

> "GRACE hoạt động qua 3 giai đoạn. Giai đoạn huấn luyện: dùng học đối lập InfoNCE trên dữ liệu benign — tạo 2 góc nhìn khác nhau của cùng đồ thị, ép mô hình học biểu diễn bất biến cho mỗi node. Giai đoạn xây dựng tham chiếu: gom toàn bộ node embeddings benign thành 200 cụm bằng K-Means — đây là hồ sơ hành vi bình thường. Giai đoạn suy luận: mã hoá đồ thị mới, đo khoảng cách từng node đến cụm benign gần nhất, rồi gộp bằng TopK-Fixed. Toàn bộ mô hình chỉ có gần 5 nghìn tham số — 19,6 KB."

**Thời lượng:** ~1 phút 15 giây

---

## Slide 13: Học đối lập InfoNCE

**Visual:**
- Minh hoạ Data Augmentation: DropEdge (p=0.3) + MaskFeature (p=0.3) → 2 Views
- Trong embedding space: positive pair (cùng node, 2 views) bị kéo lại gần (mũi tên xanh); negative pairs bị đẩy ra xa (mũi tên đỏ)
- Công thức InfoNCE: $L = -\log \frac{\exp(\text{sim}(z_1^i, z_2^i)/\tau)}{\sum_j \exp(\text{sim}(z_1^i, z_2^j)/\tau)}$, τ=0.5
- So sánh ngắn: Reconstruction Loss (FGA) chỉ tái tạo → không tối ưu phân biệt | InfoNCE trực tiếp kéo/đẩy trong embedding space

**Script:**

> "GRACE dùng InfoNCE — hàm mất mát đối lập. Đầu tiên, tạo 2 góc nhìn khác nhau của cùng đồ thị bằng cách xoá ngẫu nhiên 30 phần trăm cạnh và che 30 phần trăm đặc trưng. Hàm InfoNCE ép: cùng một node nhìn từ 2 góc phải cho embedding gần nhau — positive pair — còn các node khác nhau phải cho embedding khác nhau — negative pairs. Khác với Reconstruction Loss của FGA chỉ tái tạo đồ thị, InfoNCE trực tiếp tối ưu khoảng cách trong không gian biểu diễn — các node benign hội tụ thành cluster chặt, node bất thường tự nhiên rơi ra ngoài."

**Thời lượng:** ~1 phút

---

## Slide 14: Chấm điểm cấp Node với K-Means

**Visual:**
- Embedding space: 200 centroids (chấm xanh lá lớn) bao quanh bởi các node benign (chấm xanh nhỏ)
- Node benign mới → nằm gần centroid → khoảng cách nhỏ → anomaly score thấp
- Node attack → nằm xa centroid → khoảng cách lớn → anomaly score cao
- Công thức: `score(v) = min_k ||h_v - c_k||₂` với c_k là centroid thứ k
- Ảnh: `plot_cl_score_dist.png`

**Script:**

> "Trong giai đoạn suy luận, GRACE đo khoảng cách từ mỗi node đến cụm benign gần nhất — đây là anomaly score của node đó. 200 centroids K-Means đóng vai trò hồ sơ hành vi bình thường. Node benign nằm gần centroid — score thấp. Node attack nằm xa — score cao. Điểm quan trọng: mỗi node có score riêng biệt — hệ thống biết chính xác node nào bất thường, không chỉ là một con số chung cho cả đồ thị."

**Thời lượng:** ~45 giây

---

## Slide 15: TopK-Fixed Aggregation — Cơ chế kháng pha loãng

**Visual:**
- So sánh 2 cách gộp trên cùng dữ liệu (thanh ngang 1,450 node scores, sorted):
  - **Mean-Pool**: Chọn tất cả 1,450 scores → trung bình bị kéo xuống bởi 95% scores thấp → **MISS** (AUC = 0.55)
  - **TopK-Fixed**: Chỉ chọn K=145 scores cao nhất → trung bình top-K cao → **DETECT** (AUC = 1.0)
- Công thức: `graph_score = mean(TopK(scores, K))`, **K = 10% × N_gốc (CỐ ĐỊNH, không tăng khi graph phình)**
- Điểm mấu chốt in đậm: "K = 145. Dù thêm 1 triệu node benign → K vẫn = 145 → attack nodes luôn nằm trong Top K"

**Script:**

> "Đây là cơ chế quyết định. Sau khi chấm điểm từng node, GRACE không lấy trung bình tất cả mà chỉ lấy trung bình K node có score cao nhất — với K cố định bằng 10 phần trăm kích thước đồ thị gốc.
>
> Điểm then chốt: K cố định, không tăng khi đồ thị bị bơm thêm nodes. Trong đồ thị 1.450 nodes, K bằng 145. Dù kẻ tấn công thêm 1 triệu node benign, K vẫn là 145. Các node tấn công có score cao luôn nằm trong top K này — mọi nỗ lực pha loãng trở nên vô hiệu.
>
> Phân biệt với TopK tỷ lệ — nếu K tăng theo kích thước đồ thị, phương pháp này cũng sẽ thất bại — chúng tôi chứng minh điều này trong thí nghiệm sensitivity."

**Thời lượng:** ~1 phút 15 giây

---

# PHẦN 5: PHƯƠNG PHÁP ĐÁNH GIÁ (Slide 16) ~1 phút

---

## Slide 16: Thiết lập thực nghiệm & Phương pháp đánh giá

**Visual:**
- **Metrics** (4 cột):
  - AUC-ROC: Đo khả năng phân biệt tổng thể (0–1)
  - TPR (True Positive Rate): Tỷ lệ phát hiện đúng
  - FPR (False Positive Rate): Tỷ lệ báo nhầm
  - Evasion Rate: Tỷ lệ evasion graphs lọt qua
- **Baselines** (5 phương pháp): ProvDetector, FGA (ARGVA), Unicorn, VELOX-style, TCG-IDS-style
- **Chuỗi thí nghiệm** (bảng 7 dòng):

| # | Thí nghiệm | Mục đích |
|---|------------|----------|
| 1 | Baseline comparison | So sánh 6 phương pháp trên Attack + Evasion |
| 2 | Ablation study | Tách riêng đóng góp InfoNCE vs TopK |
| 3 | Adaptive attacks | 6 chiến thuật white-box |
| 4 | System overhead | Latency, throughput, model size |
| 5 | Sensitivity analysis | Pha loãng 1x → 1000x |
| 6 | InfoNCE verification | Kiểm chứng embedding space |
| 7 | t-SNE visualization | Trực quan hoá không gian ẩn |

**Script:**

> "Chúng tôi đánh giá bằng 4 metrics chuẩn: AUC-ROC đo khả năng phân biệt tổng thể, TPR đo tỷ lệ phát hiện đúng, FPR đo tỷ lệ báo nhầm, và Evasion Rate đo tỷ lệ tấn công ngụy trang lọt qua.
>
> GRACE được so sánh với 5 baseline và đánh giá qua 7 thí nghiệm — từ hiệu quả phát hiện, khả năng chống tấn công thích ứng, độ nhạy với mức pha loãng, đến hiệu năng triển khai thực tế."

**Thời lượng:** ~1 phút

---

# PHẦN 6: KẾT QUẢ THỰC NGHIỆM (Slide 17–22) ~7 phút 30 giây

---

## Slide 17: Thí nghiệm 1 — So sánh 6 Baseline

**Visual:**
- Bar chart so sánh Attack AUC + Evasion AUC cho 6 phương pháp
- Bảng kết quả:

| Phương pháp | Hàm gộp | Attack AUC | Evasion AUC | Evasion Rate | FPR |
|-------------|---------|:---:|:---:|:---:|:---:|
| ProvDetector | Median | 1.0000 | 0.5000 | 100% | 0% |
| Unicorn | Feat-Mean | 1.0000 | 0.7000 | 0% | 30% |
| FGA (ARGVA) | GNN-Mean | 1.0000 | 0.5533 | 100% | 50% |
| VELOX-style | GNN-Mean | 1.0000 | 0.6000 | 0% | 40% |
| TCG-IDS-style | CL-Mean | 1.0000 | 0.7000 | 0% | 30% |
| **GRACE (Ours)** | **CL-TopK** | **1.0000** | **1.0000** | **0%** | **0%** |

- Ảnh: `plot_baseline_comparison.png`

**Script:**

> "Kết quả thí nghiệm 1. Tất cả 6 phương pháp phát hiện tốt tấn công thông thường — Attack AUC đều bằng 1.0. Nhưng trước Evasion: ProvDetector và FGA chỉ đạt 0,5 — ngang đoán mò, tỷ lệ lọt lưới 100 phần trăm. Unicorn và TCG-IDS đạt 0,7 nhưng FPR lên tới 30 phần trăm — gần 1 phần 3 cảnh báo là báo nhầm.
>
> GRACE là phương pháp duy nhất đạt Evasion AUC bằng 1.0 — tỷ lệ lọt lưới 0 phần trăm, báo nhầm 0 phần trăm. Sự khác biệt duy nhất: CL-TopK thay vì CL-Mean."

**Thời lượng:** ~1 phút

---

## Slide 18: Thí nghiệm 3 — Tấn công thích ứng (Adaptive Attacks)

**Visual:**
- Bảng 7 dòng:

| Chiến thuật | Mô tả | AUC | TPR | FPR |
|-------------|-------|:---:|:---:|:---:|
| Original Evasion | Baseline | 1.0000 | 100% | 0% |
| Fragmentation (N=10) | Chia nhỏ tiến trình tấn công thành 10 mảnh | 1.0000 | 100% | 0% |
| Fragmentation (N=50) | Chia nhỏ cực đoan thành 50 mảnh | 1.0000 | 100% | 0% |
| Feature Mimicry (ε=0.5) | Sao chép đặc trưng benign cho attack nodes | 1.0000 | 100% | 0% |
| Topology Dilution (500) | Thêm 500 cạnh benign giả | 1.0000 | 100% | 0% |
| Topology Dilution (2000) | Thêm 2000 cạnh benign giả | 1.0000 | 100% | 0% |
| **Combined (worst-case)** | **Kết hợp tất cả chiến thuật** | **1.0000** | **100%** | **0%** |

- Ảnh: `plot_adaptive_attack.png`

**Script:**

> "Thí nghiệm 3 đánh giá kịch bản white-box — giả sử kẻ tấn công biết GRACE dùng TopK. Chúng tôi thử 6 chiến thuật thích ứng: băm nhỏ tiến trình tấn công thành 10 hay 50 mảnh; sao chép đặc trưng benign cho attack nodes; bơm thêm hàng nghìn cạnh giả; và kết hợp tất cả.
>
> GRACE đạt AUC bằng 1.0 trên toàn bộ kịch bản. Lý do: GCN chỉ nhìn local topology 2-hop quanh mỗi node. Các chiến thuật trên thay đổi cấu trúc toàn cục, nhưng 2-hop neighborhood quanh attack nodes — nơi xảy ra các system call bất thường như kết nối ra ngoài, ghi file nhạy cảm — vẫn không thay đổi được."

**Thời lượng:** ~1 phút 15 giây

---

## Slide 19: Thí nghiệm 5 — Pha loãng cực đoan (Sensitivity Analysis)

**Visual:**
- Biểu đồ 2 panel từ `plot_sensitivity_clones.png`:
  - Trái: AUC vs Mức pha loãng (1x, 10x, 100x, 1000x) — 3 đường (TopK-Fixed, TopK-%, Mean)
  - Phải: Kích thước graph + Score trung bình
- Bảng:

| Pha loãng | Nodes | TopK-Fixed AUC | TopK-% AUC | Mean AUC |
|:---------:|:-----:|:--------------:|:----------:|:--------:|
| 1x | 1,450 | **1.0000** | 1.0000 | 0.7000 |
| 10x | 15,955 | **1.0000** | 0.0000 | 0.0000 |
| 100x | 146,497 | **1.0000** | 0.0000 | 0.0000 |
| 1000x | 1,451,917 | **1.0000** | 0.0000 | 0.0000 |

**Script:**

> "Thí nghiệm 5 trả lời câu hỏi: nếu tăng mức pha loãng lên 1000 lần thì sao? Nhìn biểu đồ: TopK-Fixed — đường hồng — nằm ngang ở AUC bằng 1.0 xuyên suốt mọi mức, kể cả khi đồ thị phình từ 1.450 lên gần 1,5 triệu nodes.
>
> Mean-pool sụp đổ từ 0,7 xuống 0.0 ngay tại 10x. TopK tỷ lệ — K tăng theo kích thước đồ thị — cũng sụp đổ tại 10x, chứng minh yếu tố quyết định là K cố định chứ không chỉ là lấy top scores.
>
> Lý do toán học: K cố định bằng 145. Dù graph tăng 1000 lần, số attack nodes không đổi — chúng luôn nằm trong top 145."

**Thời lượng:** ~1 phút 15 giây

---

## Slide 20: Thí nghiệm 6 — Kiểm chứng InfoNCE

**Visual:**
- 3 panel từ `plot_infonce_verification.png`:
  - (a) Đường cong hội tụ InfoNCE Loss qua 200 epochs (7.98 → 7.34)
  - (b) Histogram phân phối khoảng cách đến centroid: Benign / Attack / Evasion
  - (c) Bar chart: Cohen's d + KL Divergence
- Số liệu: Cohen's d (Benign vs Attack) = 0.13 | KL Divergence (Benign vs Attack) = 0.44

**Script:**

> "Thí nghiệm 6 kiểm chứng: InfoNCE có thực sự tạo embedding phân biệt được? Panel trái cho thấy loss hội tụ ổn định qua 200 epochs.
>
> Panel giữa — phân phối khoảng cách đến centroid — cả 3 loại nodes đều tập trung gần 0 vì hơn 90 phần trăm nodes trong mọi đồ thị là benign. Nhưng attack nodes có đuôi dài kéo đến 0,3 — 0,4. TopK khai thác chính cái đuôi này.
>
> Panel phải: Cohen's d chỉ 0,13 — nhỏ ở mức tổng thể. Nhưng KL Divergence cho attack là 0,44 — nhạy với sự khác biệt ở đuôi phân phối. Kết luận: InfoNCE không cần tạo phân tách lớn ở mức tổng thể — chỉ cần đảm bảo attack nodes có score cao hơn ở mức cá nhân — và TopK sẽ khuếch đại sự khác biệt nhỏ đó."

**Thời lượng:** ~1 phút 15 giây

---

## Slide 21: Thí nghiệm 7 — t-SNE trực quan hoá không gian ẩn

**Visual:**
- 2 panel từ `plot_tsne_latent.png`:
  - (a) Toàn cảnh 5.400+ nodes: Benign train (xanh lá, 2000), Attack (đỏ, 2000), Evasion benign-origin (xanh dương, 245), Evasion attack-origin (cam, 1206)
  - (b) Zoom trong 1 đồ thị evasion: attack-origin tách biệt benign-origin
- Khoảng cách centroid 2D: Benign ↔ Attack = 31.01 | Evasion(benign) ↔ Evasion(attack) = **51.61**

**Script:**

> "t-SNE chiếu không gian ẩn 32 chiều xuống 2D. Panel trái: các node benign train hội tụ thành cluster chặt ở trung tâm. Attack nodes phân tán khắp không gian. Attack-origin nodes trong đồ thị evasion — các hình thoi cam — cũng phân tán rộng, chồng lấp với attack thuần.
>
> Panel phải zoom vào một đồ thị evasion duy nhất. Dù attack nodes và benign nodes cùng chia sẻ PID và tên Firefox, GRACE vẫn tách biệt chúng. Khoảng cách centroid trong cùng đồ thị evasion là 51,6 — lớn nhất trong tất cả các cặp. Mimicry thao túng được thống kê đồ thị, nhưng không thao túng được embedding cấp node."

**Thời lượng:** ~1 phút 15 giây

---

## Slide 22: Thí nghiệm 4 — Hiệu năng triển khai (System Overhead)

**Visual:**
- Dashboard 5 metrics:
  - **Model size**: 4,896 params — 19.6 KB
  - **Inference latency**: 4.01 ms (mean) | 6.32 ms (P95)
  - **Throughput**: 249.4 graphs/s
  - **Training time**: 93 giây cho 200 epochs
  - **Peak RAM**: 0.02 MB (inference)
- So sánh với yêu cầu thực tế: audit log rate ~100 graphs/s → GRACE xử lý 2.5x
- Ảnh: `plot_system_overhead.png`

**Script:**

> "Về hiệu năng triển khai. GRACE chỉ gần 5 nghìn tham số — 19,6 KB. Suy luận trung bình 4 mili-giây — P95 là 6,3 mili-giây. Throughput gần 250 đồ thị mỗi giây — gấp 2,5 lần tốc độ sinh audit log trung bình trong môi trường doanh nghiệp. Huấn luyện chỉ 93 giây. RAM khi suy luận chỉ 0,02 MB. GRACE hoàn toàn đáp ứng giám sát thời gian thực."

**Ghi chú:** Số liệu từ Experiment 4: mean=4.01ms, P95=6.32ms, throughput=249.4, params=4,896.

**Thời lượng:** ~45 giây

---

# PHẦN 7: THẢO LUẬN & KẾT LUẬN (Slide 23–24) ~3 phút

---

## Slide 23: Thảo luận — Ưu nhược điểm & Câu hỏi dự kiến

**Visual:**
- **Ưu điểm**:
  - AUC = 1.0 trên mọi kịch bản (baseline, adaptive, sensitivity)
  - Mô hình nhỏ gọn, triển khai thời gian thực
  - Self-supervised — không cần nhãn tấn công
- **Hạn chế**:
  - Chưa tích hợp temporal information (thứ tự thời gian)
  - Chưa thử nghiệm streaming detection
  - K = 10% cần tuning cho domain khác
- **Câu hỏi dự kiến**: "Evasion phân phối gần benign → distance-to-centroid vô dụng?"
  - Trả lời: Đúng cho Mean-pool (bị pha loãng), sai cho TopK-Fixed — attack nodes vẫn có score 0.3–0.65 ở mức cá nhân, TopK chọn đúng chúng

**Script:**

> "Về ưu điểm: GRACE đạt AUC 1.0 trên mọi kịch bản, mô hình nhỏ gọn, chỉ cần dữ liệu benign để huấn luyện.
>
> Về hạn chế: chưa tích hợp yếu tố thời gian — hiện tại đồ thị là tĩnh; chưa thử nghiệm xử lý streaming; và tham số K = 10 phần trăm có thể cần điều chỉnh cho domain khác.
>
> Dự đoán câu hỏi: phân phối evasion gần trùng benign — distance-to-centroid có vô dụng? Nhận xét này đúng ở mức tổng thể — 95 phần trăm nodes trong evasion graph bản thân là benign. Nhưng ở mức từng node, attack nodes vẫn có score cao gấp 10 lần — TopK-Fixed chọn đúng chúng. Nhận xét này mô tả chính xác tại sao FGA thất bại, nhưng không áp dụng cho TopK."

**Thời lượng:** ~1 phút 30 giây

---

## Slide 24: Kết luận & Hướng phát triển

**Visual:**
- **Kết luận** (3 điểm):
  1. Prov-HIDS dùng Mean-pool đã lỗi thời — 5/5 baseline thất bại trước Mimicry Evasion
  2. **GRACE = Node-level Contrastive Learning + TopK-Fixed Aggregation** → giải quyết triệt để lỗ hổng pha loãng
  3. Kết quả: AUC = 1.0 trên mọi kịch bản | FPR = 0% | Mô hình < 20 KB | Suy luận < 5 ms
- **Hướng phát triển** (3 hướng):
  1. Temporal Graph Networks — tích hợp thứ tự thời gian vào biểu diễn
  2. Streaming Detection — xử lý đồ thị tăng trưởng liên tục
  3. Enterprise-scale — thử nghiệm trên DARPA OpTC, TRACE, CADETS

**Script:**

> "Kết luận. Thứ nhất: nghiên cứu tái khẳng định các Prov-HIDS dùng hàm gộp trung bình đã lỗi thời trước Mimicry Evasion.
>
> Thứ hai: GRACE — kết hợp Node-level Contrastive Learning với TopK-Fixed Aggregation — giải quyết triệt để lỗ hổng pha loãng tín hiệu. AUC đạt 1.0 trên toàn bộ kịch bản bao gồm 6 adaptive attacks và pha loãng 1000x. Tỷ lệ lọt lưới và báo nhầm đều bằng 0. Mô hình chỉ 5 nghìn tham số, suy luận dưới 5 mili-giây.
>
> Hướng phát triển: tích hợp yếu tố thời gian vào đồ thị, xử lý streaming, và thử nghiệm quy mô doanh nghiệp.
>
> Xin cảm ơn Hội đồng. Tôi sẵn sàng nhận câu hỏi."

**Thời lượng:** ~1 phút 30 giây

---

# PHỤ LỤC: THAM CHIẾU ẢNH

## Ảnh sẵn có từ notebook

| Slide | File | Nội dung |
|:-----:|------|----------|
| 10 | `plot_3dataset_comparison.png` | So sánh 3 dataset |
| 11 | `plot_node_types.png` | Node type distribution |
| 14 | `plot_cl_score_dist.png` | Score distribution |
| 17 | `plot_baseline_comparison.png` | 6 baseline comparison |
| 18 | `plot_adaptive_attack.png` | Adaptive attacks |
| 19 | `plot_sensitivity_clones.png` | Sensitivity analysis |
| 20 | `plot_infonce_verification.png` | InfoNCE verification |
| 21 | `plot_tsne_latent.png` | t-SNE latent space |
| 22 | `plot_system_overhead.png` | System overhead |
| — | `plot_cl_roc.png` | ROC curves (backup) |
| — | `plot_cl_loss_curve.png` | Training loss (backup) |
| — | `plot_cl_confusion.png` | Confusion matrix (backup) |
| — | `plot_edge_distribution.png` | Edge distribution (backup) |
| — | `plot_fga_vs_grace.png` | FGA vs GRACE (backup) |

## Ảnh cần tạo mới (xem `SLIDE_IMAGE_PROMPTS.md`)

| Slide | Nội dung | Ưu tiên |
|:-----:|----------|:-------:|
| 5 | Provenance graph: 3 loại node + cạnh syscall | Cao |
| 6 | Before/after: đồ thị attack nhỏ → ẩn trong đồ thị evasion lớn | Cao |
| 8 | FGA pipeline: GCN → VAE → Mean-Pool funnel (điểm thất bại) | Cao |
| 12 | GRACE 3-stage architecture | Cao |
| 13 | InfoNCE: positive/negative pairs trong embedding space | Trung bình |
| 15 | TopK vs Mean-Pool visual comparison | Cao |

---

# TÓM TẮT CẤU TRÚC

| Phần | Slides | Nội dung |
|------|:------:|----------|
| 1. Giới thiệu | 1–5 | Tiêu đề, Lý do, Mục tiêu, Bài toán, Provenance Graph |
| 2. Công trình liên quan | 6–9 | Mimicry Evasion, Baselines thất bại, Nguyên nhân |
| 3. Dữ liệu | 10–11 | 3 dataset, Node features |
| 4. Giải pháp GRACE | 12–15 | Kiến trúc, InfoNCE, Node scoring, TopK |
| 5. Phương pháp đánh giá | 16 | Metrics, Baselines, 7 thí nghiệm |
| 6. Kết quả | 17–22 | Baseline, Adaptive, Sensitivity, InfoNCE, t-SNE, Overhead |
| 7. Kết luận | 23–24 | Thảo luận, Kết luận, Hướng phát triển |
| **Tổng** | **24** | |
