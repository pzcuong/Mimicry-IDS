# 📊 Phân tích toàn bộ Source Code

## 🎯 Tóm tắt Chung

Mục đích: **Nghiên cứu mimicry attack trên Provenance-based IDS**
- Input: Raw system call logs từ hệ thống (auditd, sysdig)
- Output: Anomaly score, đánh giá khả năng bypass IDS
- Flow: Parser → Provenance Graph → IDS (ProvDetector/PAGODA/FGA) → Evaluate

---

## 📁 Kiến trúc Module

### **1. PARSER** — Chuyển log thô → CSV Provenance Graph
```
Raw System Call Logs → Parser → CSV Provenance Graph
```

#### **parser/ssParser.py** (StreamSpot Parser)
- **Mục đích**: Parse raw audit log từ StreamSpot dataset
- **Input**: Raw system call log file (text, từ auditd/sysdig)
  - Định dạng: `ret_val, ret_time, call_time, process_name, pid, tid, syscall, arg1, arg2, ...`
- **Output**: CSV files trong thư mục `processedFiles/`
  - `output_ADM-{num}.csv` → Provenance graph (edge list)
  - `process_metadata-{num}.csv` → Thông tin process
  - `file_metadata-{num}.csv` → Thông tin file/socket
- **Xử lý chính**:
  - ✅ Validate system call (checkSyntax, checkSuccess)
  - ✅ Loại bỏ syscall không hợp lệ/không thành công
  - ✅ Gộp thread lại làm 1 process (ví dụ: các thread Firefox → 'firefox')
  - ✅ Chuẩn hóa tên process (Gecko_IOThread, Socket Thread → firefox)
  - ✅ Xây dựng đồ thị: process → file, process → socket, process → process (fork/clone/exec)
- **Key Functions**:
  - `truncateLine()` → Split line thành field
  - `checkSyntax()`, `checkSuccess()` → Validate
  - `createFiles()` → Tạo output files
  - Main loop → Process mỗi system call

**CSV Format Output** (output_ADM-{num}.csv):
```
sourceId, sourceType, destId, destType, syscal, programName, retTime, pid, [arg1, arg2]
```
Ví dụ:
```
firefox, process, /home/user/file.txt, file, write, firefox, 12345, 1234
1234, process, 5678, process, clone, firefox, 12346, 1234, 5678
```

---

#### **parser/tcParser.py** (DARPA Theia Parser)
- **Mục đích**: Parse JSON log từ DARPA Theia Transparent Computing dataset
- **Input**: JSON files từ `/data/theia/` chứa entity và edge data
- **Output**: CSV format giống ssParser
- **Xử lý**: Đọc JSON, extract process/file/socket, ghi CSV
- **Status**: Phức tạp hơn, dùng Redis để xử lý dữ liệu lớn

---

#### **parser/tcToProvParser.py, tcToSSParser.py**
- **Mục đích**: Chuyển đổi format giữa Theia → Provenance → StreamSpot format
- **Input/Output**: Tương tự, dùng để standardize format

---

### **2. PROVDETECTOR** — IDS dựa trên Path Frequency
```
Provenance Graph → Build Frequency DB → Anomaly Score (Path)
```

#### **provDetector/main.py**
- **Mục đích**: Chính của ProvDetector IDS
- **Input**: 
  - Training file (CSV provenance graph, benign data)
  - Testing file (CSV provenance graph, có thể benign/attack/evasion)
- **Output**: 
  - `freqList.data` → Frequency dictionary (pickle)
  - `setOfsets.data` → Set của nodes trong mỗi graph (pickle)
  - `{kname}_kpathsTrainingGraphs.data` → Top-K anomalous paths (pickle)
- **Flow**:
  1. Đọc training file → Xây dựng frequency database
  2. Đọc testing file → Tính anomaly score cho mỗi path
  3. Extract top-K anomalous paths (K=20 by default)
  4. Lưu results

#### **provDetector/freqDB.py**
- **Mục đích**: Xây dựng frequency database từ graph
- **Key Functions**:
  - `createFreqDict(parsedList, listOfGraphs)` → Tạo freqDict
    - **Output format**: `freqDict[(src, syscal)][dest] = frequency`
    - Ví dụ: `freqDict[('firefox', 'write')]['file.txt'] = 5` (write 5 lần)
  - `readPandasFile()` → Đọc CSV vào pandas DataFrame
  - `calculateScore()` → Tính anomaly score cho edge
    - Formula: `score = -log2(inScore × freqScore × outScore)`
    - inScore: tần suất src xuất hiện trong training
    - freqScore: tần suất (src → dest) via syscal
    - outScore: tần suất dest xuất hiện trong training
  - `getFreqScore()` → Lấy tần suất (src → dest)
  - `getInScore()`, `getOutScore()` → Lấy tần suất xuất hiện của node

**Điểm dị thường**: Path nào hiếm trong training → score cao → dáng ngờ

---

### **3. PAGODA** — IDS dựa trên Path + Threshold
```
Benign Graphs → Frequency DB → Calculate Threshold → 
Attack/Evasion Graphs → Score → Prune by Threshold → FPR/TPR/Evasion Rate
```

#### **pagoda/main.py**
- **Mục đích**: Chính của PAGODA IDS
- **Input**: 3 folders (benign, attack, evasion)
- **Output**: FPR, TPR, Evasion Rate
- **Flow**:
  1. Xây dựng freqDB từ benign graphs
  2. Tính path anomaly score cho benign/attack/evasion
  3. Xác định threshold (pathThreshold, graphThreshold)
  4. Tính metrics: FPR, TPR, evasion rate

#### **pagoda/freqDBWrapper.py**
- **Input**: List of benign CSV files
- **Output**: `freqDB` (set of frequent (src, dest) pairs)
- **Logic**: Gộp tất cả file → Tìm pairs xuất hiện ≥2 lần

#### **pagoda/pathsWrapper.py**
- **Mục đích**: Tính path frequency score
- **Input**: benign/attack/evasion files + freqDB
- **Output**: Path scores cho mỗi graph

#### **pagoda/thresholdWrapper.py**
- **Mục đích**: Xác định threshold phân tách normal vs attack
- **Input**: benPaths, attPaths, benFreqDB, attFreqDB
- **Output**: pathThreshold, graphThreshold (sử dụng ROC curve)

#### **pagoda/calcStatsWrapper.py**
- **Mục đích**: Tính FPR, TPR, evasion rate
- **Input**: Thresholds + scores
- **Output**: FPR, TPR, evasion rate

---

### **4. FGA** — IDS dựa trên Graph Autoencoder
```
Provenance Graph → Load X, edges, names → Train ARGVA → Graph Embedding → Anomaly Score
```

#### **FGA/autoencoder.py**
- **Mục đích**: Train/test ARGVA (Adversarially Regularized Graph VAE)
- **Input**: 
  - `X.pth` → Node feature vectors (shape: [num_nodes, feature_dim])
  - `edges.pth` → Edge list (shape: [2, num_edges])
  - `names.pth` → Node names + graph ID
- **Output**: 
  - `autoencoder2.pth` → Trained model (nếu train=True)
  - `graphEmbed-{nz}.pth` → Graph embeddings (nếu train=False)
- **Command**: `python autoencoder.py nz homePath trainStart trainEnd train testStart testEnd`
  - nz: embedding dimension
  - homePath: thư mục chứa X.pth, edges.pth, names.pth
  - trainStart/trainEnd: graph ID range để train
  - train: True/False
  - testStart/testEnd: graph ID range để test
- **Flow**:
  1. Load data (X, edges, names)
  2. Nếu train=True: Train ARGVA trên training graphs
  3. Nếu train=False: Encode testing graphs → lấy embeddings
  4. Lưu embeddings → dùng để so sánh anomaly score (cdist)

#### **FGA/loadFiles2.py**
- **Mục đích**: Load .pth files vào torch_geometric Data object
- **Input**: homePath chứa X.pth, edges.pth, names.pth
- **Output**: data object + names list

---

### **5. insertAttackPath.py** — Mimicry Attack Generator
```
Attack Path (pickle) + Benign Graph (CSV) + Benign Substructures → 
Insert + Camouflage → Evasion Graph (CSV)
```

#### **insertAttackPath.py**
- **Mục đích**: **Nhét** attack path vào benign graph với fake benign hành động
- **Input**:
  - `attackPath` (pickle) → List of edges [(src, dest, syscall), ...]
  - `benignFile` (CSV) → Benign provenance graph
  - `benignSubstructs` (CSV) → Benign subprocess/hành động
- **Output**: Evasion graph (CSV) → trông giống benign nhưng chứa attack
- **Key Functions**:
  - `takeOver()` → Hijack một process để thực hiện attack
  - `insertAttackPath()` → Nhét attack edges vào graph
  - `insertBenSubstructs()` → Thêm fake benign hành động để ngụy trang
  - `saveRows()` → Ghi CSV
- **Kỹ thuật**:
  - ✅ Clone process để che giấu attack
  - ✅ Thêm fake file read/write, socket connection
  - ✅ Điều chỉnh timestamp để trông tự nhiên
  - ✅ Gộp hành động vào chuỗi benign

---

## 🔄 Flow Call Tổng Thể

```
┌─────────────────────────────────────────────────────────────────┐
│                    RAW SYSTEM CALL LOGS                         │
│  (auditd/sysdig từ StreamSpot hoặc DARPA Theia dataset)        │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
        ┌────────────────────────────────────────┐
        │  PARSER (ssParser.py / tcParser.py)     │
        │  Validate, normalize, build graph      │
        └────────────────┬───────────────────────┘
                         │ CSV Provenance Graphs
                         │ (output_ADM-{num}.csv)
                         ▼
        ┌────────────────────────────────────────────────────────┐
        │              IDS OPTIONS                               │
        └────┬──────────────────────┬───────────────────┬────────┘
             │                      │                   │
             ▼                      ▼                   ▼
      ┌─────────────┐      ┌──────────────┐    ┌─────────────┐
      │ PROVDETECTOR│      │    PAGODA    │    │     FGA     │
      └─────────────┘      └──────────────┘    └─────────────┘
           │                     │                    │
    Frequency DB            Frequency DB        Graph Encoder
    Path Anomaly           Path + Threshold      ARGVA Model
           │                     │                    │
           ▼                     ▼                    ▼
    Anomaly Score         FPR/TPR/Evasion      Graph Embedding
```

### **Kịch bản 1: Train IDS**
```
Benign Graphs (CSV) 
    ▼
ProvDetector.main() / PAGODA.main() / FGA.autoencoder()
    ▼
Model/Frequency DB lưu disk (.data, .pth files)
```

### **Kịch bản 2: Test IDS**
```
Test Graphs (CSV) + Trained Model
    ▼
ProvDetector.main() / PAGODA.main() / FGA.autoencoder()
    ▼
Anomaly Scores → FPR / TPR
```

### **Kịch bản 3: Generate Evasion Attack**
```
Benign Graph (CSV) + Attack Path (pickle)
    ▼
insertAttackPath.py
    ▼
Evasion Graph (CSV) → gửi tới IDS test
    ▼
Evasion Rate = số attack graph bypass IDS / tổng attack
```

---

## 📋 Chi tiết Input/Output

### **Format CSV Provenance Graph**
```
sourceId, sourceType, destId, destType, syscal, programName, retTime, pid, [arg1, arg2, graphId(?)]
```

**Ví dụ**:
```
firefox, process, /home/user/.firefox/profile, file, open, firefox, 12345000, 1234, /home/user/.firefox/profile, 123
firefox, process, /tmp/tmpXYZ, file, write, firefox, 12345100, 1234, /tmp/tmpXYZ, 123
firefox, process, 5678, process, clone, firefox, 12345200, 1234, 5678, 123
127.0.0.1:8080, socket, firefox, process, recv, firefox, 12345300, 1234, , 123
```

### **Anomaly Score Calculation**

**ProvDetector**:
```
score = -log2(inScore × freqScore × outScore)
- inScore: P(src | training graphs)
- freqScore: P(dest | src, syscal, training)
- outScore: P(dest | training graphs)

Nếu score cao → path hiếm trong training → dáng ngờ
```

**FGA**:
```
embedding = encoder(node_features, edges)
anomaly_score = cdist(test_embedding, benign_embedding)

Nếu distance xa → embedding khác benign → dáng ngờ
```

---

## 🎯 Điểm Chính

| Module | Input | Output | Phát hiện bằng |
|--------|-------|--------|-----------------|
| **Parser** | Raw logs | CSV graph | - |
| **ProvDetector** | CSV benign + test | Anomaly scores | Path frequency |
| **PAGODA** | CSV benign/attack/evasion | FPR/TPR/evasion | Path + threshold |
| **FGA** | X.pth, edges.pth, names.pth | Embeddings | Graph encoder (ARGVA) |
| **insertAttackPath** | Attack path + benign graph | Evasion graph | Camouflage hành động |

---

## 🔧 Cách Chạy

### **1. Parse raw logs**
```bash
python parser/ssParser.py <path_to_raw_logs>
# Output: processedFiles/output_ADM-*.csv
```

### **2. Train ProvDetector**
```bash
python provDetector/main.py <training_csv> <testing_csv> <output_name>
# Output: freqList.data, setOfsets.data, kpaths*.data
```

### **3. Train PAGODA**
```bash
python pagoda/main.py <benign_dir> <attack_dir> <evasion_dir>
# Output: FPR, TPR, Evasion Rate
```

### **4. Train FGA**
```bash
python FGA/autoencoder.py 0 /path/to/data 0 100 true 0 100
# Output: autoencoder2.pth (trained model)
```

### **5. Generate Evasion Attack**
```bash
python insertAttackPath.py <attack_path.pkl> <benign.csv> <output.csv>
# Output: Evasion graph CSV
```

---

## 🎓 Ý nghĩa Thực tế

- **Mimicry Attack**: Nhét attack path vào benign graph → IDS khó phát hiện
- **Evasion Rate**: % attack graphs bypass IDS = effectiveness của mimicry
- **Evaluation**: Nếu evasion rate cao → IDS không ổn định trước mimicry attack
- **Defense**: Cần cải thiện IDS để detect được những path hiếm nhưng lành mạnh
