# PRD — MCPSentinel
### Semantic-Layer Security Scanner untuk Model Context Protocol (MCP) Servers

| | |
|---|---|
| **Status** | Draft v1.0 — Portfolio Project |
| **Author / Owner** | Genta |
| **Kategori** | AI Engineering — AI/LLM Security Tooling |
| **Terkait project lain** | Extension dari *LLM Security Evaluation Suite* (OWASP LLM Top 10 red-teaming + LLM-as-judge pipeline) |
| **Lisensi rencana** | MIT (open source) |

---

## 1. Ringkasan Eksekutif

MCPSentinel adalah security scanner open-source untuk **MCP (Model Context Protocol) server** — protokol yang jadi standar de-facto penghubung AI agent ke tools eksternal di tahun 2026. Berbeda dari scanner yang sudah ada (mayoritas berbasis pattern-matching/YARA sehingga noisy), MCPSentinel memakai pendekatan **tiga lapis**: static pattern detection, semantic intent analysis via LLM-as-judge, dan dynamic sandboxed testing — dengan tujuan utama menekan tingkat false-positive yang selama ini jadi keluhan terbesar terhadap tool sejenis.

**Elevator pitch:** *"npm audit, tapi untuk MCP server — dan tidak berisik."*

Proyek ini didesain untuk dua tujuan sekaligus: (1) jadi tool yang genuinely dipakai developer lain (publishable ke MCP Registry resmi, bisa dipasang sebagai GitHub Action), dan (2) jadi bukti teknis yang kuat di portofolio AI Engineer karena melanjutkan dan memperdalam satu garis keahlian yang sama (LLM safety evaluation) ke domain baru yang sedang tumbuh cepat.

---

## 2. Latar Belakang & Masalah

### 2.1 Konteks
MCP diperkenalkan sebagai protokol terbuka untuk menghubungkan LLM ke tools, data, dan sistem eksternal. Sejak diadopsi luas oleh mayoritas provider AI besar, jumlah MCP server publik tumbuh sangat cepat — termasuk yang dibuat komunitas tanpa proses audit keamanan yang memadai.

### 2.2 Data Masalah
- Audit keamanan terhadap ribuan MCP server publik menemukan lebih dari sepertiga server rentan terhadap SSRF, dan sekitar sepertiga dari sampel yang diperiksa memiliki kerentanan berkategori kritis.
- Kelas serangan yang sudah terdokumentasi meliputi *tool poisoning*, *rug pull* (server diam-diam mengubah definisi tool setelah dipercaya), *tool shadowing*, *cross-server attack*, dan *prompt injection* lewat deskripsi tool.
- Dua scanner open-source yang paling umum dipakai saat ini (berbasis YARA/pattern-matching) memiliki tingkat false-positive yang sangat tinggi dalam audit independen — banyak temuan ternyata cuma instruksi tool yang normal, bukan kerentanan sungguhan. Ini membuat developer cenderung mengabaikan hasil scan karena "noise fatigue".
- Sebagian besar tool yang ada berhenti di analisis statis terhadap deskripsi/skema tool — belum banyak yang benar-benar menjalankan tool di sandbox untuk menangkap perilaku yang baru muncul setelah deployment (rug pull, behavior drift).

### 2.3 Masalah Inti yang Ingin Dipecahkan
> Developer yang menyambungkan agent mereka ke MCP server pihak ketiga tidak punya cara cepat dan **presisi** untuk tahu apakah server itu aman dipasang — tool yang ada sekarang terlalu berisik (banyak false-positive) atau terlalu dangkal (cuma baca teks statis, tidak menguji perilaku nyata).

---

## 3. Tujuan Produk

### 3.1 Goals
| ID | Tujuan |
|---|---|
| G1 | Menurunkan tingkat false-positive secara signifikan dibanding baseline scanner berbasis YARA murni |
| G2 | Mendeteksi kelas kerentanan mengacu OWASP MCP Top 10 (tool poisoning, rug pull, tool shadowing, cross-server attack, confused-deputy/OAuth, dll) |
| G3 | Terintegrasi mulus ke workflow developer: CLI, CI/CD (GitHub Action, output SARIF), dan MCP-native (bisa dipanggil sebagai tool oleh agent lain) |
| G4 | Menjadi artefak portofolio yang defensible secara teknis — arsitektur dan trade-off-nya bisa dijelaskan mendalam saat interview |

### 3.2 Non-Goals (di luar cakupan v1)
- Bukan platform governance agent enterprise penuh (identity governance, permission ladder lintas organisasi)
- Bukan pengganti network firewall/egress control
- Tidak menjamin deteksi 100% — ini tool bantu, bukan jaminan keamanan mutlak
- Belum menyasar dukungan multi-bahasa server (fokus awal: server berbasis Python & TypeScript, dua ekosistem MCP terbesar)

---

## 4. Target Pengguna

| Persona | Kebutuhan |
|---|---|
| **Individual AI Developer** | Mau tahu cepat apakah MCP server pihak ketiga yang mau dia install aman, tanpa harus baca source code satu-satu |
| **Platform/Security Engineer** | Butuh gate otomatis di CI/CD sebelum MCP server baru masuk ke environment produksi tim |
| **MCP Server Maintainer** | Mau self-audit server yang dia buat sebelum publish ke registry, biar reputasinya terjaga |

---

## 5. Analisis Kompetitor & Gap

| Tool | Pendekatan | Kekuatan | Kelemahan (peluang MCPSentinel) |
|---|---|---|---|
| Cisco mcp-scanner | YARA rule matching | Cepat, ringan | False-positive tinggi, tidak paham konteks/intent |
| Invariant Labs mcp-scan / MCP-Shield | Analisis konfigurasi & deskripsi tool | Mendeteksi tool poisoning dasar | Statis, minim dynamic testing |
| Snyk agent-scan | Auto-discovery config lintas client (Claude, Cursor, dll) | Coverage discovery luas | Fokus ke discovery, deteksi kerentanan masih pattern-based |
| Proximity + NOVA | Rule engine buat prompt injection/jailbreak | Extensible rule system | Belum ada lapisan semantic judge & baseline diffing |

**Kesimpulan gap:** hampir semua tool berhenti di lapisan statis. Belum ada yang menggabungkan *semantic reasoning* (LLM-as-judge menilai apakah suatu tool description/behavior benar-benar berbahaya secara kontekstual) dengan *dynamic sandbox testing* dan *baseline diffing* dalam satu pipeline yang presisi.

---

## 6. Solusi Produk — Pendekatan Tiga Lapis

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1 — STATIC        Layer 2 — SEMANTIC     Layer 3 — DYNAMIC │
│  Pattern/YARA rule   →   LLM-as-Judge intent  →  Sandboxed tool   │
│  (cepat, baseline)       analysis (presisi)      invocation test  │
│                           ↑                                        │
│              reuse arsitektur judge pipeline dari                 │
│              LLM Security Evaluation Suite                        │
└─────────────────────────────────────────────────────────────┘
```

Setiap temuan dari Layer 1 tidak langsung dilaporkan sebagai vulnerability — melainkan diteruskan ke Layer 2 (LLM judge) untuk dinilai apakah itu pola normal atau benar-benar berisiko, baru kemudian (untuk kandidat berisiko tinggi) divalidasi lebih lanjut lewat Layer 3 (eksekusi nyata di sandbox terisolasi). Alur bertingkat ini yang jadi kunci penurunan false-positive.

---

## 7. Functional Requirements

Prioritas mengikuti MoSCoW (P0 = Must have untuk MVP, P1 = Should have, P2 = Nice to have).

| ID | Fitur | Prioritas | Deskripsi Singkat |
|---|---|---|---|
| F1 | Static Pattern Scanner | P0 | Scan skema tool/prompt/resource MCP server terhadap rule dasar (mirip YARA) sebagai filter awal cepat |
| F2 | Semantic Intent Analyzer (LLM-as-Judge) | P0 | Setiap flag dari F1 dinilai ulang oleh LLM judge untuk membedakan pola normal vs berbahaya, plus confidence score |
| F3 | Baseline Snapshot & Rug-Pull Diff | P0 | Simpan hash/snapshot definisi tool per server; deteksi perubahan diam-diam di scan berikutnya |
| F4 | CLI Tool | P0 | `mcpsentinel scan <target>` — entry point utama, output human-readable + JSON |
| F5 | SARIF Report Output | P0 | Format standar biar langsung kebaca di GitHub Code Scanning / CI lain |
| F6 | Dynamic Sandboxed Tool Invocation | P1 | Jalankan tool di container terisolasi (tanpa network egress default) untuk validasi perilaku nyata |
| F7 | GitHub Action | P1 | Drop-in action buat auto-scan MCP config setiap PR/commit |
| F8 | MCP-native Distribution | P1 | Scanner-nya sendiri dipublish sebagai MCP tool (`scan_mcp_server`) ke MCP Registry resmi, bisa dipanggil agent lain |
| F9 | Severity Scoring & HTML Risk Report | P2 | Skor severity per finding + laporan visual buat dilampirkan ke portofolio |
| F10 | Policy Config (Allow/Deny list) | P2 | Developer bisa whitelist pola tertentu yang mereka anggap aman untuk kasus mereka |

---

## 8. Non-Functional Requirements

- **Akurasi**: target false-positive rate signifikan di bawah baseline scanner YARA-only yang ada saat ini (dijadikan headline metric — lihat §12)
- **Performa**: satu scan MCP server standar (±20-30 tools) selesai dalam waktu wajar untuk dipakai di CI (bukan menit-menitan lama, layer static/semantic jadi filter dulu sebelum yang mahal — dynamic testing — dijalankan)
- **Keamanan scanner itu sendiri**: sandbox harus benar-benar terisolasi (tidak boleh scanner-nya sendiri jadi vektor serangan baru); default *no network egress* saat dynamic testing
- **Portabilitas**: CLI cross-platform (Linux/macOS minimum, mengikuti target audiens developer)
- **Extensibility**: rule engine dan judge prompt harus mudah ditambah tanpa ubah core code (plugin-style)
- **Biaya operasional**: panggilan LLM judge di-cache berdasarkan hash skema tool, supaya tidak re-analisis tool yang sama berulang-ulang di server berbeda

---

## 9. Arsitektur Sistem

**Komponen utama:**

1. **Discovery Module** — konek ke MCP server target, enumerasi tools/prompts/resources yang diekspos
2. **Static Analyzer** — rule engine pattern-matching sebagai first-pass filter
3. **Semantic Judge Module** — mengirim kandidat temuan ke LLM (Anthropic/OpenAI API — reuse langsung dari arsitektur judge di LLM Security Evaluation Suite) untuk penilaian kontekstual + confidence scoring
4. **Baseline Store** — penyimpanan snapshot (hash skema + metadata) per server untuk deteksi rug-pull di scan berikutnya
5. **Sandbox Executor** — container terisolasi untuk uji invokasi tool secara aman (dipicu hanya untuk temuan dengan confidence tinggi dari Layer 2, untuk hemat biaya/waktu)
6. **Report Generator** — output ke JSON, SARIF, dan HTML
7. **CLI / Action Interface** — entry point untuk pemakaian lokal maupun CI
8. **Registry Publisher (opsional, fase lanjut)** — wrapper agar scanner ini sendiri bisa dipanggil sebagai MCP tool

**Alur data:**
`Discovery → Static Analyzer → [kandidat berisiko] → Semantic Judge → [confidence tinggi] → Sandbox Executor → Report Generator`

---

## 10. Tech Stack (Usulan)

| Layer | Teknologi |
|---|---|
| Bahasa utama | Python 3.12+ |
| Integrasi MCP | MCP Python SDK resmi |
| LLM Judge | Anthropic Claude API / OpenAI API (reuse kredensial & prompt-design dari project sebelumnya) |
| Rule engine statis | YARA-Python atau custom pattern matcher ringan |
| Sandbox | Docker (MVP) → dievaluasi upgrade ke gVisor/Firecracker kalau perlu isolasi lebih ketat |
| Format laporan | SARIF schema resmi, Jinja2 untuk HTML report |
| CI/CD | GitHub Actions |
| Distribusi | PyPI (`pip install mcpsentinel`), Docker image, submission ke MCP Registry resmi |
| Testing | pytest + dataset "vulnerable-by-design" MCP server buatan sendiri (pola sama seperti 300-case adversarial dataset di project sebelumnya) |

---

## 11. Data Model (Entitas Utama)

- **ScanTarget** — endpoint/config MCP server yang discan, metadata koneksi
- **ToolDescriptor** — nama, deskripsi, skema parameter dari satu tool yang diekspos server
- **Finding** — kategori kerentanan, severity, evidence, confidence score, layer asal deteksi (static/semantic/dynamic)
- **BaselineSnapshot** — hash & timestamp definisi tool per server, dipakai untuk diff rug-pull
- **ScanReport** — kumpulan Finding + metadata scan, format ekspor (JSON/SARIF/HTML)

---

## 12. Success Metrics (KPI)

| Metrik | Target |
|---|---|
| False-positive rate | Turun signifikan dari baseline scanner YARA-only yang ada (dijadikan angka pembanding utama di writeup portofolio) |
| Coverage pengujian | Diuji terhadap sejumlah besar MCP server publik dari MCP Registry resmi, dibandingkan head-to-head dengan scanner lain |
| Waktu scan rata-rata | Kompetitif untuk dipakai di CI (bukan bottleneck pipeline) |
| Adopsi (proof of usefulness) | GitHub stars, jumlah repo yang pasang GitHub Action-nya, status submission ke MCP Registry resmi |

---

## 13. Roadmap (berbasis fase, tanpa target tanggal)

| Fase | Fokus |
|---|---|
| **Fase 0 — Riset & Dataset** | Kumpulkan contoh MCP server rentan (dari laporan CVE/audit publik), bangun beberapa "vulnerable-by-design" test server sendiri sebagai ground truth |
| **Fase 1 — MVP** | F1 (Static) + F2 (Semantic Judge) + F4 (CLI) + laporan JSON dasar |
| **Fase 2 — Precision & Integrasi** | F3 (Baseline diff) + F5 (SARIF) + F7 (GitHub Action) |
| **Fase 3 — Dynamic Layer** | F6 (Sandbox execution testing) |
| **Fase 4 — Distribusi & Portofolio** | F8 (MCP-native tool + submit ke Registry resmi) + F9 (HTML report) + tulis writeup/benchmark publik dibanding scanner lain |

---

## 14. Risiko & Mitigasi

| Risiko | Mitigasi |
|---|---|
| False-positive tetap tinggi meski sudah pakai LLM judge | Kalibrasi berkelanjutan pakai dataset ground-truth, confidence threshold yang bisa dikonfigurasi, opsi human-review loop |
| Biaya & latensi panggilan LLM judge membengkak | Static layer jadi filter dulu, caching berbasis hash skema tool, batch processing |
| Sandbox escape saat dynamic testing | Isolasi container ketat, default tanpa network egress, resource limit ketat |
| Isu legal/etis — scan server milik pihak lain tanpa izin | Default mode scan server publik hanya metadata (read-only); dynamic testing (F6) dibatasi hanya untuk server milik sendiri/lokal kecuali eksplisit di-enable |
| Spesifikasi MCP masih berkembang (protokol relatif baru) | Parser layer dibuat modular & versioned, mudah adaptasi kalau ada breaking change |
| Kompetisi dari vendor besar berdana kuat (Snyk, Cisco) | Positioning sebagai tool ringan, presisi, open-source, dan mudah diaudit — bukan platform enterprise all-in-one |

---

## 15. Kaitan dengan Portofolio

MCPSentinel dirancang untuk melanjutkan narasi teknis yang sudah terbentuk dari dua project sebelumnya:

- **LLM Security Evaluation Suite** → sumber langsung arsitektur judge pipeline dan pendekatan red-teaming berbasis OWASP Top 10, sekarang diterapkan ke domain baru (OWASP MCP Top 10)
- **Real-Time Fraud Detection & Model Monitoring** → konsep baseline snapshot & diff detection (F3) meminjam logika yang sama dengan drift detection (PSI/KS) yang sudah pernah dibangun, hanya domainnya berpindah dari data drift ke *behavior drift* pada tool MCP

Dengan begini, tiga project membentuk satu garis cerita yang konsisten: **membangun sistem yang membuat AI/agent bisa dipercaya untuk dijalankan di produksi** — bukan tiga project acak yang tidak nyambung satu sama lain.

---

## 16. Open Questions

- Nama final produk: tetap "MCPSentinel" atau ada alternatif lain yang mau dipertimbangkan?
- Open-source sejak hari pertama, atau dikembangkan privat dulu sampai MVP matang baru dipublish?
- Perlu bikin landing page/demo terpisah, atau cukup README + GitHub Action sebagai showcase utama?

---

## 17. Referensi

- Data statistik kerentanan MCP server (SSRF, kerentanan kritis, tool poisoning) — hasil kompilasi riset keamanan MCP 2026, Practical DevSecOps
- Audit independen tingkat false-positive scanner MCP berbasis YARA — AppSec Santa Research, April 2026
- Perbandingan Cisco mcp-scanner vs Invariant Labs mcp-scan — AppSec Santa Research, April 2026
- Snyk agent-scan (GitHub: snyk/agent-scan)
- Proximity open-source MCP scanner + NOVA rule engine — Help Net Security, Oktober 2025