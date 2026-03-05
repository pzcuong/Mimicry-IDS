# Báo Cáo Kỹ Thuật: FGA — Hệ Thống Phát Hiện Xâm Nhập Dựa Trên Provenance Graph

> **Mục đích:** Giải thích toàn diện ý tưởng, kiến trúc, pipeline dữ liệu và kết quả của mô hình FGA (Fake Graph Autoencoder) trong bối cảnh nghiên cứu evasion attack chống lại IDS.

---

## Mục Lục

1. [Bối Cảnh & Động Lực](#1-bối-cảnh--động-lực)
2. [Tổng Quan Hệ Thống](#2-tổng-quan-hệ-thống)
3. [Dataset — Nguồn Gốc & Cấu Trúc](#3-dataset--nguồn-gốc--cấu-trúc)
4. [Pipeline Dữ Liệu: Từ Raw Logs đến Input Model](#4-pipeline-dữ-liệu-từ-raw-logs-đến-input-model)
5. [Mô Hình FGA: Ý Tưởng & Kiến Trúc](#5-mô-hình-fga-ý-tưởng--kiến-trúc)
6. [Step-by-Step: Train & Inference](#6-step-by-step-train--inference)
7. [Evasion (Mimicry) Attack](#7-evasion-mimicry-attack)
8. [Kết Quả Thực Nghiệm](#8-kết-quả-thực-nghiệm)
9. [Tại Sao FGA Thất Bại Trước Evasion?](#9-tại-sao-fga-thất-bại-trước-evasion)
10. [Glossary](#10-glossary)

---

## 1. Bối Cảnh & Động Lực

### 1.1 Vấn đề: Tấn công APT không để lại dấu vết rõ ràng

**APT (Advanced Persistent Threat)** — các tấn công tinh vi, kéo dài — rất khó phát hiện bằng các IDS truyền thống (signature-based, anomaly threshold) vì:

- Không tạo ra file malware rõ ràng
- Sử dụng công cụ hợp pháp của hệ thống (`python`, `ps`, `chmod`)
- Hoạt động chậm, tránh "burst" traffic
- Log thông thường (firewall, antivirus) không đủ ngữ cảnh

### 1.2 Giải pháp: Provenance Graph — IDS

**Provenance graph** là đồ thị có hướng ghi lại **toàn bộ luồng thông tin** của hệ thống ở cấp kernel:

```
Mọi syscall đều được ghi lại:
  firefox (process) --[write]--> cache.db (file)
  python  (process) --[read]---> /etc/passwd (file)
  socket  (socket)  --[recv]---> firefox (process)
```

**Lợi thế:** Cung cấp **ngữ cảnh nhân quả** đầy đủ — biết chính xác process nào, đọc/ghi file nào, qua syscall gì, vào lúc nào. Không thể giả mạo hoặc xóa sau khi xảy ra.

### 1.3 Ba IDS trong nghiên cứu này

| IDS | Ý tưởng cốt lõi | Phương pháp |
|---|---|---|
| **ProvDetector** | Đường đi hiếm = bất thường | Path frequency scoring |
| **PAGODA** | Kết hợp path + ngưỡng thống kê | Statistical threshold |
| **FGA** | Toàn bộ đồ thị benign vs bất thường | Graph Autoencoder (ARGVA) |

---

## 2. Tổng Quan Hệ Thống

### Luồng xử lý tổng thể

```
┌─────────────────────────────────────────────────────────────────┐
│                    HỆ THỐNG MÁY TÍNH (Linux)                    │
│                                                                  │
│  Process A → syscall → Process B                                 │
│  Process A → syscall → File C                                    │
│  Socket D  → syscall → Process A                                 │
│                  │                                               │
│         Linux auditd / SystemTap                                 │
│         (ghi lại mọi syscall ở cấp kernel)                       │
└──────────────────┬──────────────────────────────────────────────┘
                   │ Raw audit logs
                   ▼
           ┌──────────────┐
           │  ssParser.py │  ← xử lý log text thô
           │  tcParser.py │  ← xử lý DARPA CDM JSON
           └──────┬───────┘
                  │ Provenance CSV (human-readable edges)
                  ▼
         ┌─────────────────┐
         │ Feature Engineer│  ← chuyển graph → tensor
         └────────┬────────┘
                  │ X.pth (node features) + edges.pth
                  ▼
         ┌─────────────────┐      ┌───────────────┐
         │   FGA (ARGVA)   │◄─────│  Train set    │
         │   Model Train   │      │ (benign only) │
         └────────┬────────┘      └───────────────┘
                  │ fga_trained.pth
                  ▼
         ┌─────────────────┐
         │   Inference     │  ← embed test graphs
         │   + Scoring     │  ← min-distance to train
         └────────┬────────┘
                  │ anomaly_score per graph
                  ▼
         ┌─────────────────┐
         │    Decision     │  score > threshold → ALERT
         └─────────────────┘
```

---

## 3. Dataset — Nguồn Gốc & Cấu Trúc

### 3.1 Nguồn dữ liệu: DARPA Transparent Computing — Theia

**DARPA TC** là chương trình nghiên cứu của Bộ Quốc phòng Mỹ nhằm thu thập provenance data từ các hệ thống thực tế trong điều kiện có tấn công được kiểm soát.

- **Hệ điều hành:** Linux Ubuntu
- **Ghi nhận:** SystemTap intercept toàn bộ syscall ở kernel level
- **Hoạt động benign ghi lại:** Browse web (Firefox), download file, xem YouTube, Gmail, CNN, chơi game
- **Tấn công ghi lại:** Python-based attack script, data exfiltration, privilege escalation

### 3.2 Cấu trúc file CSV (Provenance format)

Mỗi file CSV = 1 provenance graph. Mỗi dòng = 1 cạnh có hướng:

```
sourceId, sourceType, destId, destType, syscal, processName, retTime, pid, arg1, arg2
```

**Ví dụ thực tế:**

```
usr/bin/systemTap, process, "/usr/bin/python", process, execve, stapio, 3657800, 9599, python, [...]
/lib/i386-linux-gnu/libpthread.so.0, file, "/usr/bin/python", process, read, python, 4087668, 9599, , 
/etc/passwd, file, "/usr/bin/python", process, read, python, 5123400, 9599, ,
"/usr/bin/python", process, /tmp/out.txt, file, write, python, 6234500, 9599, ,
```

**Ý nghĩa từng cột:**

| Cột | Kiểu | Ý nghĩa | Ví dụ |
|---|---|---|---|
| `sourceId` | string | Node nguồn: đường dẫn file / địa chỉ socket / tên process | `/etc/passwd`, `192.168.1.1:80` |
| `sourceType` | string | Loại node nguồn | `process`, `file`, `socket` |
| `destId` | string | Node đích | `/usr/bin/python` |
| `destType` | string | Loại node đích | `process`, `file`, `socket` |
| `syscal` | string | System call được thực hiện | `read`, `write`, `recv`, `execve` |
| `processName` | string | Tên tiến trình thực hiện | `python`, `firefox`, `ps` |
| `retTime` | int64 | Timestamp khi syscall kết thúc (nanoseconds) | `3657800` |
| `pid` | int64 | Process ID (tạm thời, do OS cấp) | `9599` |
| `arg1` | string | Tham số syscall (hầu hết rỗng) | `[python cnn.py]` |
| `arg2` | string | Tham số syscall (hầu hết rỗng) | *(trống)* |

### 3.3 Định dạng thứ hai: StreamSpot format

Cùng một dữ liệu nhưng encode ngắn gọn hơn (1 ký tự/type) để xử lý nhanh:

```
nodeId  srcType  nodeId  dstType  edgeType  graphId
  1       c        0       a        v         0
  2       a        4       c        G         0
```

**Bảng giải mã ký tự** (từ `tcToSSParser.py`):

| Ký tự | Loại node | | Ký tự | Syscall |
|---|---|---|---|---|
| `a` | process | | `v` | read |
| `b` | thread | | `G` | write |
| `c` | file | | `w` | recv |
| `e` | socket | | `z` | send |
| | | | `p` | execve |
| | | | `m` | clone |
| | | | `F` | waitpid |

### 3.4 Thống kê dataset

| Split | Số files | Tổng cạnh | TB cạnh/graph | Vai trò |
|---|---|---|---|---|
| **Benign Train** | 70 (sample 20) | 1,475,646 | 73,782 | Train model (chỉ benign) |
| **Benign Test** | 30 (sample 10) | 756,927 | 75,693 | Đánh giá FPR |
| **Attack** | 100 (sample 20) | 112,766 | 5,638 | Đánh giá TPR |
| **Evasion** | 100 (sample 20) | 2,428,570 | 121,428 | Đánh giá evasion rate |

> **Quan sát:** Evasion graph lớn hơn Attack ~21× và lớn hơn Benign ~1.6× — đây là dấu hiệu trực tiếp của kỹ thuật mimicry injection.

---

## 4. Pipeline Dữ Liệu: Từ Raw Logs đến Input Model

### 4.1 Bước 1: Thu thập log (ssParser / tcParser)

```
INPUT:
┌─────────────────────────────────────────────────────┐
│  Raw SystemTap log (text):                           │
│  ret_val, ret_time, call_time, process_name, pid,   │
│  tid, syscall, arg1, arg2, ...                       │
│                                                      │
│  HOẶC                                                │
│                                                      │
│  DARPA CDM JSON:                                     │
│  {"datum": {"com.bbn.tc.schema.avro.cdm18.          │
│  Event": {"uuid": "...", "type": "EVENT_READ", ...}} │
└─────────────────────────────────────────────────────┘
                         │
                         ▼  ssParser.py (text log)
                            tcParser.py (CDM JSON)
                         │
                         │  Xử lý:
                         │  - Phân tích cú pháp từng syscall
                         │  - Theo dõi file descriptors (fd table)
                         │  - Theo dõi socket descriptors (sd table)
                         │  - Resolve UUID → human-readable names
                         │  - Map fd → actual file path (via open/close)
                         │  - Map sd → actual socket address (via connect)
                         │
OUTPUT:
┌─────────────────────────────────────────────────────┐
│  Provenance CSV:                                     │
│  /etc/passwd, file, python, process, read,           │
│    python, 5123400, 9599, ,                          │
└─────────────────────────────────────────────────────┘
```

**Tại sao phức tạp?** File descriptor là số nguyên tạm thời (FD 3, 4, 5...). Parser phải theo dõi bảng FD để biết FD 4 đang trỏ đến `/etc/passwd` hay `/tmp/data.txt`. Tương tự với socket — phải theo dõi từ lúc `connect()` để biết socket trỏ đến IP nào.

### 4.2 Bước 2: Xây dựng Provenance Graph

```
INPUT:  Provenance CSV (danh sách cạnh)

Mỗi dòng là 1 cạnh: (source, srcType, dest, dstType, syscall, ...)
         │
         ▼  Xây dựng đồ thị có hướng
         │
         ├─ Nodes: mọi entity xuất hiện (process / file / socket)
         │         → Assign integer ID
         │
         └─ Edges: cạnh có hướng + nhãn syscall
                   → Có thể multi-edge (cùng cạnh xuất hiện nhiều lần)

OUTPUT: Provenance Graph G = (V, E)
         V = {process nodes, file nodes, socket nodes}
         E = {directed edges labelled by syscall type}
```

**Ví dụ đồ thị tấn công:**

```
        stapio
           │ execve
           ▼
        python ──read──► /etc/passwd
           │             /proc/net/tcp
           │ write       /home/user/.ssh/id_rsa
           ▼
        /tmp/stolen.txt
           │
           │ (sau đó send qua socket)
           ▼
       192.168.1.100:4444 (attacker)
```

### 4.3 Bước 3: Feature Engineering (CSV → PyTorch Tensor)

```
INPUT:  Provenance Graph G = (V, E)
        (dạng CSV file)

         │
         ▼
┌────────────────────────────────────────────────────────┐
│  BƯỚC 3.1: NODE ENUMERATION                            │
│                                                        │
│  Gom tất cả sourceId + destId → dict                   │
│  {"/etc/passwd" → 0, "python" → 1, "socket_X" → 2...} │
│                                                        │
│  → N = tổng số node unique trong graph                 │
└────────────────────────────────────────────────────────┘
         │
         ▼
┌────────────────────────────────────────────────────────┐
│  BƯỚC 3.2: NODE FEATURE MATRIX X ∈ ℝ^(N × 8)          │
│                                                        │
│  Với mỗi node i, tính vector 8 chiều:                  │
│                                                        │
│  [0] = 1 nếu nodeType == 'process', else 0             │
│  [1] = 1 nếu nodeType == 'file',    else 0             │
│  [2] = 1 nếu nodeType == 'socket',  else 0             │
│  [3] = degree_in(i)   (số cạnh đến node i)             │
│  [4] = degree_out(i)  (số cạnh đi từ node i)           │
│  [5] = 1 nếu syscall phổ biến nhất tại node = 'write' │
│  [6] = 1 nếu syscall phổ biến nhất tại node = 'read'  │
│  [7] = 1 nếu syscall phổ biến nhất tại node = 'recv'  │
│                                                        │
│  → Ma trận X shape: (N_nodes, 8)                       │
└────────────────────────────────────────────────────────┘
         │
         ▼
┌────────────────────────────────────────────────────────┐
│  BƯỚC 3.3: EDGE INDEX ∈ ℤ^(2 × E)                     │
│                                                        │
│  edge_index[0] = [src_id_0, src_id_1, src_id_2, ...]  │
│  edge_index[1] = [dst_id_0, dst_id_1, dst_id_2, ...]  │
│                                                        │
│  → Tensor shape: (2, E_edges)                          │
└────────────────────────────────────────────────────────┘
         │
         ▼
OUTPUT:
  X.pth      ← node feature matrix  shape (N, 8)
  edges.pth  ← edge index           shape (2, E)
  names.pth  ← node ID → name mapping
```

**Ví dụ minh hoạ cho 1 graph nhỏ:**

```
Graph nhỏ:
  python(process) --read--> /etc/passwd(file)
  python(process) --write-> /tmp/out.txt(file)

Node enumeration:
  python      → ID=0,  type=process,  degree_in=0, degree_out=2
  /etc/passwd → ID=1,  type=file,     degree_in=0, degree_out=1
  /tmp/out.txt→ ID=2,  type=file,     degree_in=1, degree_out=0

Feature matrix X (shape 3×8):
  node 0: [1, 0, 0,  0, 2,  0, 1, 0]  ← process, din=0, dout=2, top_syscall=read
  node 1: [0, 1, 0,  0, 1,  0, 1, 0]  ← file,    din=0, dout=1, top_syscall=read
  node 2: [0, 1, 0,  1, 0,  1, 0, 0]  ← file,    din=1, dout=0, top_syscall=write

Edge index (shape 2×2):
  [[0, 0],   ← source: python, python
   [1, 2]]   ← dest:   /etc/passwd, /tmp/out.txt
```

---

## 5. Mô Hình FGA: Ý Tưởng & Kiến Trúc

### 5.1 Ý tưởng cốt lõi

**FGA sử dụng chiến lược One-Class Classification:**

> *"Chỉ học từ dữ liệu BÌNH THƯỜNG. Mọi thứ xa lạ so với bình thường đều là bất thường."*

**Ưu điểm:** Không cần dữ liệu tấn công khi train — trong thực tế, ta không biết trước các loại tấn công mới sẽ như thế nào.

**Cơ chế:**
1. **Train** trên benign graphs → model học cách "nén" và "tái tạo" đồ thị bình thường hiệu quả
2. **Test** bằng cách embed graph mới và đo khoảng cách đến vùng "bình thường"
3. **Alert** nếu khoảng cách vượt ngưỡng

### 5.2 Tại sao dùng Graph Autoencoder?

Provenance graph có cấu trúc **quan hệ phức tạp** — không thể đơn giản flatten thành vector. Graph Neural Network (GNN) có thể học được:
- Thông tin cấu trúc cục bộ (neighborhood)
- Lan truyền thông tin qua nhiều hop
- Biểu diễn mỗi node trong ngữ cảnh của cả đồ thị

**ARGVA** (Adversarially Regularized Graph Variational Autoencoder) = VGAE + GAN regularization → latent space có phân phối chuẩn N(0,I) → khoảng cách Euclidean có ý nghĩa.

### 5.3 Kiến trúc chi tiết ARGVA

```
INPUT:
  X ∈ ℝ^(N × 8)          ← N nodes, mỗi node 8 features
  edge_index ∈ ℤ^(2 × E) ← E cạnh

                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                   ENCODER (GCN-based)                   │
│                                                         │
│  Layer 1: GCNConv(8 → 32)                               │
│    H = ReLU(D^{-½} · A · D^{-½} · X · W₁)              │
│    H ∈ ℝ^(N × 32)                                       │
│                         │                               │
│            ┌────────────┴────────────┐                  │
│            ▼                         ▼                  │
│  Layer 2a: GCNConv(32 → 16)  Layer 2b: GCNConv(32 → 16)│
│    μ = H·W_μ               log σ² = H·W_σ              │
│    μ ∈ ℝ^(N × 16)          log σ² ∈ ℝ^(N × 16)        │
│                                                         │
│  Reparameterization trick:                              │
│    ε ~ N(0, I)                                          │
│    z = μ + ε ⊙ exp(0.5 · log σ²)                        │
│    z ∈ ℝ^(N × 16)          ← NODE EMBEDDINGS           │
└──────────────────────────┬──────────────────────────────┘
                           │ z
               ┌───────────┴───────────┐
               │                       │
               ▼                       ▼
┌──────────────────────┐  ┌────────────────────────────┐
│       DECODER        │  │      DISCRIMINATOR (MLP)   │
│  (Inner Product)     │  │                            │
│                      │  │  Lin(16 → 32) → ReLU       │
│  Â = σ(z · zᵀ)      │  │  Lin(32 → 32) → ReLU       │
│                      │  │  Lin(32 → 1)  → Sigmoid    │
│  Reconstruct adj.    │  │                            │
│  matrix from z       │  │  Phân biệt:                │
│                      │  │  z (posterior q(z|X,A))    │
│  → Compare with A    │  │  vs ẑ ~ N(0,I) (prior)     │
└──────────────────────┘  └────────────────────────────┘
         │  L_recon               │  L_adv
         └──────────┬─────────────┘
                    │
                    ▼
          TOTAL LOSS = L_recon + L_KL + L_adv

OUTPUT:
  z ∈ ℝ^(N × 16)  ← Node-level embeddings

GRAPH EMBEDDING (mean pool):
  g = (1/N) Σᵢ zᵢ  ∈ ℝ^16  ← Scalar vector đại diện toàn graph
```

### 5.4 Graph Convolutional Network (GCN) — Giải thích trực quan

GCN cập nhật embedding của mỗi node bằng cách **tập hợp thông tin từ hàng xóm**:

```
h_v^(l+1) = σ( W^(l) · AGGREGATE({h_u : u ∈ N(v) ∪ {v}}) )

Nghĩa là: embedding mới của node v = 
  hàm học (W) của trung bình có trọng số các embedding hàng xóm của v
```

Trong GCN chuẩn (paper Kipf & Welling 2017):

$$H^{(l+1)} = \sigma\left(\tilde{D}^{-\frac{1}{2}} \tilde{A} \tilde{D}^{-\frac{1}{2}} H^{(l)} W^{(l)}\right)$$

Trong đó:
- $\tilde{A} = A + I$ (adjacency matrix + self-loops)
- $\tilde{D}$ = degree matrix của $\tilde{A}$
- $W^{(l)}$ = ma trận trọng số học được

**Ý nghĩa thực tế cho provenance graph:**
- Sau layer 1: Mỗi node biết về **bản thân và hàng xóm trực tiếp** (1-hop)
- Sau layer 2: Mỗi node biết về **2-hop neighborhood** → một process biết cả những file mà hàng xóm của nó đọc/ghi

### 5.5 Hàm Loss: Ba thành phần

$$\mathcal{L}_{\text{total}} = \mathcal{L}_{\text{recon}} + \mathcal{L}_{\text{KL}} + \mathcal{L}_{\text{adv}}$$

**Thành phần 1 — Reconstruction Loss** $\mathcal{L}_{\text{recon}}$:

$$\mathcal{L}_{\text{recon}} = -\sum_{(i,j)} \left[ A_{ij} \log \hat{A}_{ij} + (1 - A_{ij}) \log(1 - \hat{A}_{ij}) \right]$$

- Yêu cầu: decoder phải tái tạo lại adjacency matrix từ z
- Nếu model học tốt: z chứa đủ thông tin cấu trúc graph

**Thành phần 2 — KL Divergence Loss** $\mathcal{L}_{\text{KL}}$:

$$\mathcal{L}_{\text{KL}} = \text{KL}\left(q(z|X,A) \| p(z)\right) = \text{KL}\left(\mathcal{N}(\mu, \sigma^2) \| \mathcal{N}(0, I)\right)$$

$$= \frac{1}{2} \sum_j \left(\mu_j^2 + \sigma_j^2 - \log \sigma_j^2 - 1\right)$$

- Yêu cầu: phân phối z phải gần với prior N(0,I)
- Mục đích: regularization → tránh overfitting, latent space có cấu trúc

**Thành phần 3 — Adversarial Loss** $\mathcal{L}_{\text{adv}}$:

$$\mathcal{L}_{\text{adv}} = \mathbb{E}[\log D(\tilde{z})] + \mathbb{E}[\log(1 - D(z))]$$

- $\tilde{z} \sim \mathcal{N}(0, I)$ (samples từ prior)
- Discriminator D cố phân biệt z thật (từ encoder) với z giả (từ prior)
- Encoder cố đánh lừa D → z phải giống N(0,I) thực sự
- Tác dụng: áp đặt prior mạnh hơn KL term → latent space sạch hơn

---

## 6. Step-by-Step: Train & Inference

### Phase 1: TRAINING (chỉ dùng benign graphs)

```
┌──────────────────────────────────────────────────────────────────┐
│ INPUT: 15 benign training graphs                                  │
│        X_train shape (21,379 nodes × 8 features)                 │
│        E_train shape (2 × 1,150,385 edges)                        │
└──────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────▼─────────────────────┐
        │              EPOCH LOOP (300 lần)          │
        │                                            │
        │  Step A: ENCODER FORWARD PASS              │
        │    H = GCNConv₁(X, E) → ReLU              │
        │    μ = GCNConv_μ(H, E)                     │
        │    logσ² = GCNConv_σ(H, E)                 │
        │    z = μ + ε·σ  (ε ~ N(0,I))              │
        │                                            │
        │  Step B: DISCRIMINATOR UPDATE (×5 lần)    │
        │    ẑ ~ N(0, I)  (sample prior)             │
        │    L_disc = BCE(D(z), 0) + BCE(D(ẑ), 1)  │
        │    backward → update discriminator         │
        │                                            │
        │  Step C: ENCODER UPDATE                    │
        │    Â = σ(z·zᵀ)  (decoder)                 │
        │    L_recon = BCE(Â, A)                     │
        │    L_KL = KL(N(μ,σ²) ‖ N(0,I))            │
        │    L_adv = -E[log D(z)]  (fool disc.)      │
        │    L_total = L_recon + L_KL + L_adv       │
        │    backward → update encoder               │
        └─────────────────────┬─────────────────────┘
                              │
                              │ Epoch 1:   loss = 19.35
                              │ Epoch 50:  loss =  4.53
                              │ Epoch 100: loss =  3.03
                              │ Epoch 300: loss =  2.58
                              │
                              ▼
                     Lưu model → fga_trained.pth
```

### Phase 2: INFERENCE & SCORING

```
┌──────────────────────────────────────────────────────────────────┐
│ INPUT: Tập train graphs + graph cần đánh giá (test/attack/evade) │
└──────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────▼─────────────────────┐
        │  BƯỚC 1: BUILD TRAIN REFERENCE            │
        │                                            │
        │  Với mỗi graph G_i trong train set:        │
        │    z_i = encoder(X_i, E_i)  [no gradient] │
        │    g_i = mean(z_i)  ∈ ℝ¹⁶                 │
        │                                            │
        │  → train_embeddings = [g₁, g₂, ..., g₁₅] │
        │     shape: (15, 16)                        │
        └─────────────────────┬─────────────────────┘
                              │
        ┌─────────────────────▼─────────────────────┐
        │  BƯỚC 2: EMBED TEST GRAPH                 │
        │                                            │
        │  z_test = encoder(X_test, E_test)          │
        │  g_test = mean(z_test)  ∈ ℝ¹⁶              │
        └─────────────────────┬─────────────────────┘
                              │
        ┌─────────────────────▼─────────────────────┐
        │  BƯỚC 3: ANOMALY SCORE                    │
        │                                            │
        │  score = min_j ‖g_test - g_j‖₂            │
        │                                            │
        │  = khoảng cách Euclidean tối thiểu         │
        │    từ g_test đến tập train embeddings      │
        └─────────────────────┬─────────────────────┘
                              │
        ┌─────────────────────▼─────────────────────┐
        │  BƯỚC 4: DECISION                         │
        │                                            │
        │  if score > threshold:                     │
        │      → ALERT (anomaly detected)            │
        │  else:                                     │
        │      → NORMAL (benign)                     │
        └───────────────────────────────────────────┘
```

### Ví dụ minh hoạ Anomaly Scores thực tế

```
                 Latent Space ℝ¹⁶ (projected to 2D)

          g_train_1 ●
                     ● g_train_2
                  ● g_train_3    ← Cụm BENIGN (chặt, gần nhau)
               ●
          g_train_4 ●
                        ● g_test_benign  score = 0.0005 ✅ NORMAL

                                               ● g_attack
                                          score = 0.0365 ❌ ALERT!

                        ● g_evasion
                    score = 0.0002 ✅ (bị nhầm là NORMAL)
```

---

## 7. Evasion (Mimicry) Attack

### 7.1 Ý tưởng tấn công

Kẻ tấn công biết FGA sử dụng graph embedding + nearest-neighbor scoring. Để qua mặt:

> *"Nếu tôi thêm đủ nhiều cạnh BENIGN vào đồ thị tấn công,*
> *embedding kết quả sẽ bị kéo về vùng BENIGN."*

### 7.2 Cơ chế injection

```
ATTACK GRAPH (gốc):
  python → /etc/passwd    [read]      ← tấn công thực sự
  python → /proc/net/tcp  [read]
  python → /tmp/out.txt   [write]
  python → 192.168.1.100  [send]
  
  Tổng: ~5,638 cạnh. Score = 0.0365 → BỊ PHÁT HIỆN!

         +

BENIGN INJECTION (~115,790 cạnh):
  firefox → cache_db.sqlite   [write]    ←┐
  socket  → firefox           [recv]      │ Copy-paste từ
  firefox → plugins.json      [write]     │ benign graph
  socket  → firefox           [recv]      │ thực tế
  firefox → cert9.db          [write]    ←┘
  ... (lặp lại hàng chục nghìn lần)

         =

EVASION GRAPH:
  Tổng: ~121,428 cạnh
  95.4% cạnh là benign, 4.6% là attack
  
  Score = 0.0002 → KHÔNG BỊ PHÁT HIỆN ✓
```

### 7.3 Tại sao kỹ thuật này hiệu quả?

```
MEAN POOLING là điểm yếu:

g = (1/N) Σᵢ zᵢ

Trong EVASION graph:
  N_total = N_benign + N_attack
  N_benign ≈ 20 × N_attack

Vậy:
  g ≈ (20·z_benign_avg + 1·z_attack_avg) / 21
    ≈ 0.952 × z_benign + 0.048 × z_attack
    ≈ z_benign  (tín hiệu attack bị pha loãng 20 lần!)
```

### 7.4 So sánh attack graph vs evasion graph

| Đặc điểm | Attack (raw) | Evasion (mimicry) |
|---|---|---|
| Số cạnh | 5,638 | 121,428 |
| % cạnh attack | 100% | 4.6% |
| % cạnh benign injected | 0% | 95.4% |
| Process names | `python`, `ps` | `python`, `ps` + `firefox`, `plugin-container` |
| Syscall pattern | `read`-heavy | `write`/`recv`-heavy (bị dilute) |
| Anomaly score | **0.0365** | **0.0002** |
| Bị phát hiện? | ❌ Có (100%) | ✅ Không (0%) |

---

## 8. Kết Quả Thực Nghiệm

### 8.1 Anomaly Scores

| Split (n=graphs) | Mean Score | Std | Min | Max | Phân tích |
|---|---|---|---|---|---|
| Train benign (15) | 0.0000 | 0.0000 | 0.0000 | 0.0000 | Điểm tham chiếu (dist=0 với chính mình) |
| Test benign (10) | 0.0005 | 0.0004 | 0.0000 | 0.0012 | Gần train → benign bình thường |
| **Attack (15)** | **0.0365** | 0.0000 | 0.0365 | 0.0365 | **73× so với benign → anomaly rõ ràng** |
| **Evasion (15)** | **0.0002** | 0.0000 | 0.0002 | 0.0002 | **< benign test mean → bị coi là normal!** |

### 8.2 Threshold & Decision

Threshold được chọn theo **Youden's J = max(TPR - FPR)** trên ROC curve:

```
SCENARIO 1 — ATTACK DETECTION:

  Score distribution:
    Benign: ████████ (0.0000 → 0.0012)
    Attack:                              ████████ (0.0365)
    
    Gap = 30×  → PERFECT separation
    
  Threshold = 0.0365 (Youden's J optimal)
  
  TPR = 15/15 = 100%  (tất cả attack bị bắt)
  FPR =  0/10 =   0%  (không có false alarm)
  AUC = 1.0000 ← PERFECT


SCENARIO 2 — EVASION DETECTION:

  Score distribution:
    Benign:  ████ (0.0000 → 0.0012)
    Evasion: ██   (0.0002)           ← NẰM TRONG VÙNG BENIGN!
    
    → Không có threshold nào tách được sạch
    
  Best threshold = 0.0002 (Youden's J)
  
  TPR = 15/15 = 100%  (detect evasion)
  FPR =  5/10 =  50%  (nhầm lẫn benign → không chấp nhận được)
  
  Nếu dùng "safe" threshold (FPR=0, tức thr > 0.0012):
    → 0/15 evasion bị phát hiện
    → Evasion Rate = 100%
    
  AUC = 0.5533 ← GẦN RANDOM (0.5)
```

### 8.3 Metrics tổng hợp

| Metric | Attack | Evasion | Ý nghĩa |
|---|---|---|---|
| **ROC-AUC** | 🟢 1.000 | 🔴 0.553 | 1.0 = perfect, 0.5 = random |
| **Average Precision** | 🟢 1.000 | 🔴 0.589 | Tương tự AUC nhất quán |
| **Detection Rate** | 🟢 100% | 🔴 0% | % tấn công bị phát hiện |
| **Evasion Rate** | 🟢 0% | 🔴 100% | % tấn công QUA MẶT IDS |
| **False Positive Rate** | 🟢 0% | 🔴 50% | % benign bị cảnh báo nhầm |

### 8.4 Confusion Matrices

**Scenario 1: Attack (thr = 0.0365)**
```
                  Pred: Benign    Pred: Threat
  True: Benign  │     10      │      0     │  → FPR = 0%
  True: Threat  │      0      │     15     │  → TPR = 100%
```

**Scenario 2: Evasion (thr = 0.0002, Youden's J)**
```
                  Pred: Benign    Pred: Threat
  True: Benign  │      5      │      5     │  → FPR = 50% ⚠
  True: Threat  │      0      │     15     │  → TPR = 100%
```

---

## 9. Tại Sao FGA Thất Bại Trước Evasion?

### 9.1 Nguyên nhân cơ bản: Mean-Pool Aggregation quá nhạy cảm

```
Graph embedding = TRUNG BÌNH của N node embeddings
                = Bị DOMINATEd bởi node nhiều nhất
                  
Nếu 95% node là benign:
  g ≈ 0.95 × g_benign + 0.05 × g_attack
  g ≈ g_benign  ← về cơ bản là benign embedding
```

### 9.2 Nguyên nhân thứ cấp: GCN message passing bị pha loãng

```
Trong evasion graph, attack node bị bao quanh bởi benign neighbors:

  benign₁ ──────────────────────────────── benign₂
      \                                     /
       ──── benign₃ ──── attack ──── benign₄ ────
      /                                     \
  benign₅ ──────────────────────────────── benign₆

GCN aggregation cho attack node:
  h_attack = f(h_attack_prev, h_benign₃, h_benign₄)
            ≈ DOMINATED bởi benign neighbors

→ Attack node embedding bị kéo về phía benign!
```

### 9.3 Các điểm yếu khác

| Điểm yếu | Mô tả | Giải pháp tiềm năng |
|---|---|---|
| **Mean-pool** | Average bị pha loãng bởi benign | Max-pool / Attention-pool |
| **Node-centric** | Không phân biệt tỉ lệ node types | Weighted scoring theo type |
| **Graph-level only** | Không score từng subgraph | Subgraph anomaly detection |
| **Static threshold** | Threshold cố định, không adaptive | Online/dynamic threshold |
| **Size-blind** | Không phát hiện graph inflation | Normalize by graph size |

---

## 10. Glossary

| Thuật ngữ | Giải thích |
|---|---|
| **Provenance Graph** | Đồ thị có hướng ghi lại luồng thông tin hệ thống: ai làm gì, với file/process nào, lúc nào |
| **APT** | Advanced Persistent Threat — tấn công tinh vi, kéo dài, khó phát hiện |
| **Syscall** | System Call — giao tiếp giữa user-space process và kernel (read, write, recv, execve...) |
| **Auditd / SystemTap** | Công cụ ghi log kernel-level trên Linux |
| **GCN** | Graph Convolutional Network — mạng nơ-ron học trên đồ thị |
| **ARGVA** | Adversarially Regularized Graph Variational Autoencoder |
| **Autoencoder** | Mạng học cách nén (encode) và tái tạo (decode) input — loss cao = input xa lạ |
| **VAE** | Variational Autoencoder — thêm ràng buộc probabilistic vào latent space |
| **GAN** | Generative Adversarial Network — encoder và discriminator thi đấu nhau |
| **Latent Space** | Không gian ẩn chiều thấp mà model nén dữ liệu vào |
| **Mean Pooling** | Tính trung bình vector của tất cả nodes để đại diện graph |
| **Anomaly Score** | Điểm đo mức độ "xa lạ" so với dữ liệu bình thường đã học |
| **One-Class Classification** | Train chỉ trên dữ liệu bình thường, flag anything else là bất thường |
| **ROC-AUC** | Area Under ROC Curve — đo khả năng phân biệt 2 class (1.0 = perfect, 0.5 = random) |
| **Youden's J** | J = TPR - FPR, threshold tối ưu hóa J được chọn trên ROC curve |
| **TPR / Recall** | True Positive Rate = % threats bị phát hiện đúng |
| **FPR** | False Positive Rate = % benign bị cảnh báo nhầm |
| **Evasion Rate** | % tấn công QUA được IDS mà không bị phát hiện |
| **Mimicry Attack** | Tấn công ngụy trang bằng cách copy-paste hành vi benign |
| **FD (File Descriptor)** | Số nguyên tạm thời đại diện file đang mở trong process |
| **DARPA TC** | DARPA Transparent Computing — chương trình thu thập provenance data với tấn công thực |

---

*Báo cáo này được tổng hợp từ mã nguồn (`FGA/autoencoder.py`, `FGA/loadFiles2.py`, `parser/*.py`), kết quả thực nghiệm từ `analysis.ipynb`, và dataset DARPA Theia.*
