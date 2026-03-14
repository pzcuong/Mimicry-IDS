# Prompt Tạo Ảnh Minh Hoạ Cho Slides

> **Phong cách chung cho tất cả prompt:** Clean academic illustration, white background, flat design, 1920x1080, sans-serif font, no 3D effects, minimal text — let shapes and colors tell the story. Color palette: blue #2196F3, red #E53935, green #4CAF50, orange #FF9800, purple #9C27B0, gold #FFC107.

---

## Slide 2: Provenance Graph

```
A clean technical diagram of a system provenance graph on white background. 1920x1080.

Three types of nodes arranged in a natural left-to-right flow:
- 3 PROCESS nodes as rounded blue rectangles with gear icons inside, labeled "bash", "firefox", "python"
- 3 FILE nodes as green document icons with folded corner, labeled "/etc/passwd", "/tmp/cache", "/var/log"
- 2 SOCKET nodes as orange diamond shapes with wifi/signal icon, labeled "192.168.1.1" and "10.0.0.5"

Curved directed arrows connect them, each arrow has a tiny pill-shaped label:
  bash──(clone)──►firefox──(write)──►/tmp/cache
  firefox──(connect)──►192.168.1.1
  python──(read)──►/etc/passwd
  bash──(exec)──►python──(sendto)──►10.0.0.5

Along the bottom, a thin gray timeline arrow labeled "time →" with small tick marks.

Top-right corner: a small legend box with three colored circles showing "Process | File | Socket".

Style: vector illustration, thin arrow lines (1.5px), subtle drop shadows on nodes, plenty of whitespace between nodes, looks like a textbook figure.
```

---

## Slide 4: Mimicry Evasion — Before vs After

```
A dramatic before-and-after comparison on white background. 1920x1080.

LEFT (30% width): A small tight cluster of about 12 red nodes connected by red arrows, forming a compact attack graph. The entire cluster fits inside a red dashed circle. Label above: "Attack Graph" with a small badge "5,640 edges". The nodes glow faintly red.

CENTER (15% width): A large bold horizontal arrow, gradient from red to blue, with a padlock-breaking icon on it. Below the arrow: "Mimicry Evasion".

RIGHT (55% width): A massive cloud of approximately 80 small blue dots densely interconnected with thin light-blue lines, forming a huge benign graph. Deep inside this blue cloud, barely visible, the same 12 red nodes from the left are embedded — connected to blue nodes through a single shared node labeled "firefox" (half blue, half red, like a Trojan horse). Label above: "Evasion Graph" with badge "121,429 edges".

Below the right cloud: a thin horizontal stacked bar, 95% filled blue, 5% filled red. Labels: "95.4% benign noise" and "4.6% attack signal".

The visual contrast should be striking: tiny red cluster on left → hidden inside massive blue cloud on right.
```

---

## Slide 7: insertAttackPath.py Pipeline

```
A vertical 4-step pipeline flowchart on white background. 1920x1080.

Four large rounded rectangle stages connected by thick downward arrows:

STAGE 1 (blue, icon: CSV file):
  A small blue graph icon (6 nodes, 8 edges). Label: "Load Benign Graph".

  ↓ thick gray arrow

STAGE 2 (orange, icon: mask/disguise):
  Shows a blue process node being overlaid with a red shadow — the "hijack". A curved arrow wraps around the node. Label: "Hijack Firefox Process".

  ↓ thick gray arrow

STAGE 3 (green, icon: copy/clone):
  Multiple small blue graph fragments (3-4 tiny clusters) being poured/injected into a larger blue graph — like pouring water into a pool. Label: "Inject Benign Noise". Small annotation: "numberOfClones".

  ↓ thick gray arrow

STAGE 4 (red, icon: syringe/needle):
  A small red graph fragment being carefully inserted into the center of the now-massive blue graph — like hiding a needle in a haystack. Label: "Insert Attack Path".

  ↓ thick gray arrow

OUTPUT (dark gray rounded box):
  A large mixed graph icon: massive blue cloud with tiny red core. Two small badges: blue "95%" and red "5%". Label: "Evasion Graph".

Style: each stage box has matching colored left border (4px), white fill, subtle shadow. Icons are simple flat vector, not photo-realistic.
```

---

## Slide 9: FGA Architecture — Why It Fails

```
A horizontal left-to-right architecture pipeline on white background. 1920x1080.

Five blocks connected by thick arrows:

BLOCK 1 — "Input Graph":
  A small provenance graph icon with ~10 nodes (mix of blue and 2 red nodes). Red nodes slightly glow.

  ══► arrow

BLOCK 2 — "GCN Encoder" (blue gradient block, trapezoid shape narrowing right):
  Inside: two stacked horizontal bars labeled "Layer 1: 8→64" and "Layer 2: 64→32". Small circular arrows around nodes suggest message-passing. The 2 red node embeddings are still distinct (red dots among blue dots) at the output.

  ══► arrow

BLOCK 3 — "VAE" (purple block):
  A bottleneck hourglass shape. Input: many colored dots (32-dim per node). Output: same dots but slightly compressed. Label: "μ, σ → z".

  ══► arrow

BLOCK 4 — "MEAN-POOL" (bright RED block with warning stripes ⚠️, visually the largest and most prominent):
  This is the critical failure point. Visual: many individual dots (blue and red) being funneled into a single large circle — like a funnel. The output is ONE single gray dot. The red dots are completely invisible in the mixed average.
  A large red X overlays this block.
  Below: red text "Bottleneck: 95% blue drowns 5% red"

  ══► arrow

BLOCK 5 — "Score" (gray block):
  A single number "0.55" displayed large, with a stamp "≈ RANDOM" in red.

The overall visual story: red signal enters on the left, survives through GCN and VAE, but gets DESTROYED at the Mean-Pool funnel.
```

---

## Slide 10: "Classroom" Analogy

```
An infographic-style illustration split into top and bottom halves. White background. 1920x1080.

TOP HALF — "The Classroom":
A 10×10 grid of 100 small circular student avatars (simple flat faces).
97 avatars are BLUE with a subtle smile.
3 avatars are RED with a subtle suspicious look — scattered at random positions in the grid (e.g., row 3 col 5, row 7 col 2, row 9 col 8). Hard to spot among the blue ones.
Above the grid: "Evasion Graph = 100 students"

BOTTOM HALF — split into LEFT and RIGHT:

BOTTOM-LEFT — "Mean-Pool Teacher" (red-tinted panel):
A teacher silhouette with a calculator icon.
A funnel graphic: all 100 avatars pour in → one single number comes out: "92.5"
A speech bubble: "All normal!"
Red stamp at bottom: "MISSED ✗" — "AUC = 0.55"

BOTTOM-RIGHT — "TopK Teacher" (green-tinted panel):
A teacher silhouette with a magnifying glass icon.
Instead of a funnel, a FILTER graphic: the grid is shown with the top-10 worst scores highlighted in a gold spotlight. The 3 red students are clearly visible in the spotlight along with 7 blue students.
A speech bubble: "Found them!"
Green stamp at bottom: "DETECTED ✓" — "AUC = 1.00"

Style: friendly infographic but professional enough for thesis defense. Simple geometric avatars, not cartoon characters. Clear visual contrast between left (failure, red tint) and right (success, green tint).
```

---

## Slide 14: GRACE Architecture (3 Stages)

```
A comprehensive architecture diagram with three distinct horizontal stages, separated by vertical dashed lines. White background. 1920x1080.

STAGE 1 — "TRAINING" (left third, light blue background tint):

A provenance graph icon at far left.
Two branches split from it (Y-shape):
  - Upper branch: graph with some edges shown as dashed/removed (DropEdge). Arrow into a blue trapezoid "GCN Encoder".
  - Lower branch: graph with some node features shown as grayed-out squares (MaskFeature). Arrow into the SAME blue trapezoid (dashed line connects the two trapezoids showing "shared weights").

Both branches output clusters of colored dots (embeddings) that flow into a red rounded box labeled "InfoNCE Loss" — visualized as a magnet pulling matching dots together (green arrows between same-node pairs) and pushing non-matching dots apart (red arrows).

STAGE 2 — "REFERENCE" (middle third, light green background tint):

The trained encoder (blue trapezoid, now with a snowflake icon = frozen) processes many benign graphs → outputs thousands of green dots → these dots flow into a K-Means cluster visualization showing ~8 visible cluster centroids as large green circles with smaller dots around them.
Label: "200 Benign Centroids"

STAGE 3 — "INFERENCE" (right third, light gold background tint):

A new unknown graph (with question mark) → frozen encoder → produces node embeddings (mix of green and red dots).
Each dot has a thin dashed line measuring distance to nearest green centroid.
Red dots are far from centroids (long lines). Blue/green dots are close (short lines).
These distances feed into a golden funnel/filter labeled "TopK" — only the top-K highest scores pass through.
Output: a single score badge "0.647" with green checkmark "ATTACK DETECTED".

Style: pipeline diagram, left-to-right flow across 3 stages, each stage has its own subtle background color tint, consistent iconography, the visual tells the complete story even without reading labels.
```

---

## Slide 15: InfoNCE — Pull Together, Push Apart

```
A conceptual 2D embedding space visualization on white background. 1920x1080.

CENTER — a large circle representing the embedding space:

A tight cluster of ~20 small GREEN dots in the center-left area, labeled "Benign cluster".

One specific node highlighted:
- A BLUE star (★) labeled "node i, view 1"
- A BLUE star outline (☆) nearby labeled "node i, view 2"
- A thick GREEN spring/elastic band connects them, with arrow labeled "PULL" — they are being pulled together.

Scattered around the space: 6-8 RED triangles at various distances from the blue star.
Each red triangle has a thin RED repulsion arrow pushing it AWAY from the blue star, labeled "PUSH".

The visual metaphor: the blue star pair is like two magnets attracting, while all red triangles are like same-pole magnets repelling.

LEFT inset box (small, 20% width):
Two mini-graphs side by side:
- Graph with 2 edges crossed out in red (X marks) → "View 1 (DropEdge)"
- Graph with 2 nodes grayed out → "View 2 (MaskFeature)"

RIGHT inset box (small, 20% width):
"After 200 epochs" — shows the green cluster even tighter, and red triangles pushed far out to the edges of the circle.

Style: conceptual diagram (not real data), clean geometric shapes, the spring/elastic visual between positive pairs is the key metaphor, academic but intuitive.
```

---

## Slide 17: TopK vs Mean-Pool — The Key Difference

```
A side-by-side visual comparison on white background. 1920x1080.

TOP — shared element:
A long horizontal bar representing 1,450 node scores sorted from low to high.
The leftmost ~1,300 segments are light blue (low scores, benign).
The rightmost ~145 segments transition from yellow to orange to bright red (high scores).
Among the red section, 5 segments have tiny skull/warning icons = attack nodes.
Label above: "Same Evasion Graph: 1,450 node anomaly scores (sorted)"

BOTTOM-LEFT — "Mean-Pool (FGA)" panel with red border:
The same bar, but ALL segments are selected (highlighted with a translucent red overlay).
Below: a funnel graphic — all 1,450 scores pour in, one average score comes out.
The output score shown as a small blue thermometer reading very LOW (barely above zero).
Visual: the massive blue section overwhelms the tiny red tail.
Red stamp: "MISS" with "AUC = 0.55"

BOTTOM-RIGHT — "TopK-Fixed (GRACE)" panel with green border:
The same bar, but ONLY the rightmost 145 segments are selected (highlighted with a golden glow). The left 1,305 segments are completely grayed out / faded.
Below: a filter/sieve graphic — only 145 high scores pass through.
The output score shown as a thermometer reading very HIGH (deep red).
Visual: the 5 attack nodes are clearly visible among the 145 selected.
Green stamp: "CATCH" with "AUC = 1.00"

A callout arrow points to the golden section: "K = 145 (FIXED). Graph grows 1000× → K stays 145."

Style: the visual metaphor is a spotlight/filter vs a funnel. The contrast between grayed-out (ignored by TopK) and highlighted (selected) should be immediately obvious.
```

---

## Ảnh sẵn có từ notebook (dùng trực tiếp, không cần tạo)

| Slide | File | Nội dung |
|:-----:|------|----------|
| 19 | `plot_baseline_comparison.png` | Bar chart 6 baseline |
| 20 | `plot_adaptive_attack.png` | 6 adaptive attacks |
| 22 | `plot_sensitivity_clones.png` | Sensitivity: AUC vs dilution |
| 23 | `plot_infonce_verification.png` | InfoNCE: loss + histogram + metrics |
| 24 | `plot_tsne_latent.png` | t-SNE scatter 4 categories |
| 21 | `plot_system_overhead.png` | System overhead dashboard |
| — | `plot_cl_roc.png` | ROC curves (backup) |
| — | `plot_cl_score_dist.png` | Score distribution (backup) |
| — | `plot_fga_vs_grace.png` | FGA vs GRACE (backup) |

## Tóm tắt ảnh cần tạo

| Slide | Mô tả | Ưu tiên |
|:-----:|-------|:-------:|
| **2** | Provenance graph: 3 loại node + cạnh syscall | Cao |
| **4** | Before/after: nhỏ đỏ → ẩn trong đám mây xanh lớn | Cao |
| **7** | Pipeline 4 bước dọc: load → hijack → noise → inject | Trung bình |
| **9** | FGA pipeline: GCN → VAE → **Mean-Pool funnel** (phá huỷ tín hiệu) | Cao |
| **10** | 100 avatar: 97 xanh + 3 đỏ, Mean teacher vs TopK teacher | Cao |
| **14** | GRACE 3-stage: Training (InfoNCE) → Reference (K-Means) → Inference (TopK) | Cao |
| **15** | Embedding space: spring kéo positive pair, đẩy negative pairs | Trung bình |
| **17** | Sorted bar: Mean chọn tất cả (miss) vs TopK chọn đuôi phải (catch) | Cao |
