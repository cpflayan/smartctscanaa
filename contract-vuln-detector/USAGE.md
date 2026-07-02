# Contract Vulnerability Detector - 使用說明

AI 驅動的區塊鏈安全漏洞掃描工具，支援本地合約與鏈上合約掃描，以及即時監控功能。

---

## 目錄

- [環境需求](#環境需求)
- [安裝](#安裝)
- [設定](#設定)
- [指令總覽](#指令總覽)
- [scan - 漏洞掃描](#scan---漏洞掃描)
- [watch - 即時監控](#watch---即時監控)
- [whitelist - 白名單管理](#whitelist---白名單管理)
- [fetch - 抓取合約](#fetch---抓取合約)
- [chains - 查看支援鏈](#chains---查看支援鏈)
- [全域參數](#全域參數)
- [掃描工具說明](#掃描工具說明)
- [監控模式說明](#監控模式說明)
- [通知系統](#通知系統)
- [設定檔參考](#設定檔參考)
- [使用範例](#使用範例)

---

## 環境需求

- Python 3.10+
- Slither（靜態分析）：`pip install slither-analyzer`
- Mythril（符號執行）：`pip install mythril`
- Watchdog（檔案監控）：`pip install watchdog`
- Web3（鏈上互動）：`pip install web3`

---

## 安裝

```bash
cd contract-vuln-detector
pip install -r requirements.txt
pip install slither-analyzer mythril watchdog web3
```

設定 API Key（鏈上掃描需要）：

```bash
export ETHERSCAN_API_KEY="your-api-key"
export OPENAI_API_KEY="your-api-key"    # AI 分析需要
```

---

## 指令總覽

| 指令 | 說明 |
|------|------|
| `scan` | 掃描合約漏洞（本地檔案或鏈上） |
| `watch` | 即時監控合約變更、事件、交易、新部署、深度偵查 |
| `whitelist` | 管理合約白名單（list / add / remove / clear） |
| `fetch` | 抓取鏈上合約原始碼（不掃描） |
| `chains` | 列出所有支援的區塊鏈及狀態 |

---

## scan - 漏洞掃描

掃描 Solidity 合約，偵測安全漏洞並產生報告。

### 語法

```bash
python main.py scan [選項]
```

### 選項

| 參數 | 短寫 | 說明 | 預設值 |
|------|------|------|--------|
| `--file` | `-f` | 本地 `.sol` 檔案路徑 | - |
| `--address` | `-a` | 鏈上合約地址（`0x...`） | - |
| `--chain` | - | 區塊鏈名稱 | `ethereum` |
| `--scanner` | `-s` | 指定掃描工具（`pattern` / `slither` / `mythril`） | 全部 |
| `--no-ai` | - | 跳過 AI 深度分析 | `false` |
| `--output` | `-o` | 報告輸出目錄 | `./reports` |

> `--file` 和 `--address` 至少指定一個。

### 範例

```bash
# 掃描本地檔案
python main.py scan -f examples/VulnerableBank.sol

# 掃描鏈上合約（Polygon）
python main.py scan -a 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174 --chain polygon

# 只用 pattern 掃描器（速度最快）
python main.py scan -f examples/VulnerableBank.sol -s pattern

# 跳過 AI 分析（純腳本模式）
python main.py scan -f examples/VulnerableBank.sol --no-ai

# 指定輸出目錄
python main.py scan -f examples/VulnerableBank.sol -o ./my-reports
```

### 掃描流程

1. **載入原始碼** — 從本地檔案或鏈上 Explorer API 抓取
2. **執行掃描** — 平行運行所有啟用的掃描工具
3. **AI 分析** — 對每個發現進行深度分析（攻擊路徑、影響、修復建議）
4. **產生報告** — 輸出 JSON 和 Markdown 格式的审计报告

### 輸出

報告自動儲存至 `./reports/` 目錄：

```
reports/
  ├── VulnerableBank_20260702_110716.json   # 機器可讀報告
  └── VulnerableBank_20260702_110716.md     # 人類可讀 Markdown 報告
```

---

## watch - 即時監控

持續監控鏈上合約或本地檔案，發現異常時即時通知。

### 語法

```bash
python main.py watch [選項]
```

### 選項

| 參數 | 短寫 | 說明 | 預設值 |
|------|------|------|--------|
| `--address` | `-a` | 監控的合約地址（可重複） | - |
| `--chain` | `-c` | 區塊鏈名稱（可重複，逗號分隔） | `ethereum` |
| `--file-dir` | `-d` | 監控的本地目錄（可重複） | - |
| `--interval` | - | 定期重掃間隔（秒） | `300` |
| `--poll-interval` | - | 鏈上輪詢間隔（秒） | `12` |
| `--modes` | - | 啟用的監控模式（逗號分隔） | `rescan,events,tx` |
| `--log-file` | - | 日誌輸出路徑 | `./reports/monitor.log` |
| `--no-ai` | - | 觸發掃描時跳過 AI 分析 | `false` |
| `--output` | `-o` | 報告輸出目錄 | `./reports` |
| `--whitelist-file` | - | 白名單 JSON 檔路徑 | `./reports/whitelist.json` |
| `--no-auto-whitelist` | - | 停用掃描後自動加入白名單 | `false` |

### 監控模式

| 模式 | 說明 | 需要地址 |
|------|------|----------|
| `rescan` | 定期重新抓取原始碼，變更時自動重掃 | 是 |
| `events` | 監聽合約事件（Transfer、Approval 等） | 是 |
| `tx` | 監控目標合約的交易 | 是 |
| `deploy` | 監控鏈上新合約部署 | 否 |
| `txscan` | 掃描鏈上所有交易涉及的合約（深度偵查） | 否 |

### 範例

```bash
# 監控本地目錄（檔案變更自動重掃）
python main.py watch -d ./examples

# 監控鏈上合約（所有模式）
python main.py watch -a 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174 \
  --chain polygon --modes rescan,events,tx

# 只監控新合約部署（不指定地址）
python main.py watch --chain polygon --modes deploy

# 監控多條鏈的新部署
python main.py watch -c polygon,bsc,arbitrum --modes deploy

# 重複指定多條鏈
python main.py watch -c polygon -c bsc -c arbitrum --modes deploy

# 同時監控鏈上 + 本地
python main.py watch -a 0x地址 --chain polygon -d ./contracts --modes rescan,events

# 自訂輪詢間隔（每 5 秒檢查一次）
python main.py watch -a 0x地址 --chain polygon --poll-interval 5

# 跳過 AI 分析（加快掃描速度）
python main.py watch -d ./examples --no-ai

# 深度偵查：掃描鏈上所有交易涉及的合約
python main.py watch -c polygon --modes txscan

# 多鏈深度偵查 + 自動白名單
python main.py watch -c polygon,bsc --modes txscan

# 深度偵查 + 部署監控
python main.py watch -c polygon --modes deploy,txscan
```

### 停止監控

按 `Ctrl+C` 停止。

---

## whitelist - 白名單管理

管理合約白名單。通過深度掃描無問題的合約會自動加入白名單，後續掃描自動跳過。

### 語法

```bash
python main.py whitelist [子指令] [選項]
```

### 子指令

| 子指令 | 說明 |
|--------|------|
| `list` | 列出所有白名單合約 |
| `add` | 手動加入合約到白名單 |
| `remove` | 從白名單移除合約 |
| `clear` | 清空白名單 |

### 範例

```bash
# 列出所有白名單
python main.py whitelist list

# 按鏈篩選
python main.py whitelist list --chain polygon

# 手動加入白名單
python main.py whitelist add -a 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174 --chain polygon --reason "USDC trusted"

# 移除白名單
python main.py whitelist remove -a 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174 --chain polygon

# 清空白名單（需確認）
python main.py whitelist clear

# 只清空特定鏈
python main.py whitelist clear --chain polygon
```

### 自動白名單機制

- 監控掃描完成後，若無發現漏洞（或僅有 low/info 等級），自動加入白名單
- 白名單合約在後續監控中自動跳過掃描
- 可透過 `--no-auto-whitelist` 停用自動加入
- 可透過 `config/settings.yaml` 的 `whitelist.auto_add_max_severity` 調整門檻

---

## fetch - 抓取合約

從鏈上抓取合約原始碼並顯示資訊（不進行掃描）。

### 語法

```bash
python main.py fetch --address <地址> [--chain <鏈>]
```

### 選項

| 參數 | 短寫 | 說明 | 預設值 |
|------|------|------|--------|
| `--address` | `-a` | 合約地址（必填） | - |
| `--chain` | - | 區塊鏈名稱 | `ethereum` |

### 範例

```bash
# 抓取 Ethereum 上的合約
python main.py fetch -a 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48

# 抓取 Polygon 上的合約
python main.py fetch -a 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174 --chain polygon
```

---

## chains - 查看支援鏈

列出所有支援的區塊鏈及其設定狀態。

### 語法

```bash
python main.py chains
```

### 範例

```bash
python main.py chains
```

輸出：

```
Supported chains:

  ethereum     (chain_id: 1) API key: configured
  bsc          (chain_id: 56) API key: NOT SET
  polygon      (chain_id: 137) API key: configured
  arbitrum     (chain_id: 42161) API key: NOT SET
  optimism     (chain_id: 10) API key: NOT SET
```

---

## 全域參數

以下參數可搭配任何指令使用：

| 參數 | 短寫 | 說明 |
|------|------|------|
| `--config` | `-c` | 指定設定檔路徑（預設 `config/settings.yaml`） |
| `--verbose` | `-v` | 啟用除錯日誌 |

```bash
# 啟用除錯模式
python main.py -v scan -f examples/VulnerableBank.sol

# 使用自訂設定檔
python main.py -c my-config.yaml scan -f examples/VulnerableBank.sol
```

> 注意：`watch` 指令的 `-c` 是 `--chain` 的縮寫，全域 `-c` 為 `--config`。在 `watch` 中使用 `--config` 指定設定檔。

---

## 掃描工具說明

| 工具 | 類型 | 說明 | 速度 |
|------|------|------|------|
| `pattern` | 正則匹配 | 掃描常見漏洞模式（重入、tx.origin 等） | 最快 |
| `slither` | 靜態分析 | 使用 Slither 框架進行深度靜態分析 | 中等 |
| `mythril` | 符號執行 | 使用 Mythril 進行符號執行分析 | 最慢 |

預設平行運行所有啟用的工具。可用 `--scanner` 只運行特定工具。

---

## 監控模式說明

### rescan - 定期重新掃描

- 每隔 N 秒透過 Explorer API 重新抓取合約原始碼
- 計算 SHA256 雜湊值與上次比對
- 原始碼變更時自動觸發完整掃描流程
- 適用場景：監控已部署合約是否被升級

### events - 事件監聽

- 使用 `eth_getLogs` 輪詢合約的 Event Logs
- 即時偵測 Transfer、Approval 等事件
- 適用場景：監控代幣轉移、授權變更

### tx - 交易監控

- 輪詢最新區塊，篩選發送至目標合約的交易
- 記錄交易來源、金額、雜湊值
- 適用場景：監控合約互動活動

### deploy - 新部署監控

- 輪詢區塊，篩選 `to=null` 的合約創建交易
- 發現新部署後嘗試抓取原始碼並自動掃描
- 不需要指定地址，可監控整條鏈
- 適用場景：偵測新部署的潛在惡意合約

### txscan - 交易深度偵查

- 輪詢區塊中所有交易，針對每筆交易的目标合約進行深度掃描
- 自動抓取合約原始碼（需已驗證），執行完整掃描流程
- 同一合約只掃描一次（去重），白名單合約自動跳過
- 掃描無問題後自動加入白名單，後續不再重複掃描
- 不需要指定地址，可監控整條鏈
- 適用場景：主動偵查鏈上活躍合約的安全性

---

## 通知系統

監控發現事件時，透過三種管道通知：

| 管道 | 說明 |
|------|------|
| 終端機 | 即時彩色輸出警示至螢幕 |
| 日誌檔 | 寫入 `./reports/monitor.log` |
| 自動報告 | 呼叫 ReportGenerator 產生 JSON/Markdown 報告 |

### 通知事件類型

| 事件 | 說明 |
|------|------|
| `合約原始碼變更` | 鏈上合約原始碼被修改 |
| `鏈上事件` | 合約觸發 Event Log |
| `可疑交易` | 目標合約收到交易 |
| `新合約部署` | 鏈上部署了新合約 |
| `交易觸發深度掃描` | txscan 模式發現並掃描合約 |
| `掃描完成` | 掃描結束，顯示發現數量 |
| `已加入白名單` | 合約通過掃描後自動加入白名單 |
| `白名單跳過` | 白名單合約被跳過 |
| `本地檔案變更` | 本地 .sol 檔案被修改 |

---

## 設定檔參考

設定檔位於 `config/settings.yaml`：

```yaml
# LLM API 設定（AI 分析用）
llm:
  provider: "openai"          # openai | ollama | azure
  api_key: "${OPENAI_API_KEY}"
  model: "gpt-4"
  temperature: 0.1
  max_tokens: 4096

# 掃描工具設定
scanners:
  slither:
    enabled: true
    timeout: 300
    detectors:                 # 啟用的 Slither 偵測器
      - reentrancy-eth
      - tx-origin
      - ...
  mythril:
    enabled: true
    timeout: 300
    execution_timeout: 60
    strategy: "bfs"
    max_depth: 50
  pattern:
    enabled: true

# 區塊鏈設定（Etherscan V2 統一 API）
chains:
  ethereum:
    chain_id: 1
    explorer_api: "https://api.etherscan.io/v2/api"
    explorer_key: "${ETHERSCAN_API_KEY}"
    rpc_url: "https://eth.llamarpc.com"
  polygon:
    chain_id: 137
    explorer_api: "https://api.etherscan.io/v2/api"
    explorer_key: "${ETHERSCAN_API_KEY}"
    rpc_url: "https://polygon-bor-rpc.publicnode.com"
  # ... 更多鏈

# 報告設定
reports:
  output_dir: "./reports"
  formats: [json, markdown]
  include_code_snippets: true
  max_snippet_lines: 20

# 監控設定
monitor:
  interval: 300            # 定期重掃間隔（秒）
  poll_interval: 12        # 鏈上輪詢間隔（秒）
  file_debounce: 2.0       # 檔案變更去抖動（秒）
  log_file: "./reports/monitor.log"
  modes: [rescan, events, tx, deploy]

# 白名單設定
whitelist:
  auto_add: true                # 掃描後自動加入白名單
  auto_add_max_severity: "low"  # 自動加入的最高嚴重等級門檻
  filepath: "./reports/whitelist.json"
```

---

## 使用範例

### 情境 1：快速掃描本地合約

```bash
python main.py scan -f examples/VulnerableBank.sol --no-ai
```

### 情境 2：完整掃描鏈上合約（含 AI 分析）

```bash
python main.py scan -a 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174 --chain polygon
```

### 情境 3：開發時即時監控

```bash
# 監控合約開發目錄，修改 .sol 檔案自動重掃
python main.py watch -d ./contracts --no-ai
```

### 情境 4：監控鏈上重要合約

```bash
# 監控 USDC 合約的事件和交易
python main.py watch \
  -a 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174 \
  --chain polygon \
  --modes events,tx \
  --poll-interval 5
```

### 情境 5：監控多鏈新部署

```bash
python main.py watch -c polygon,bsc,arbitrum --modes deploy
```

### 情境 6：全方位監控

```bash
# 同時監控鏈上合約 + 本地開發目錄 + 新部署
python main.py watch \
  -a 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174 \
  -c polygon,ethereum \
  -d ./contracts \
  --modes rescan,events,tx,deploy \
  --interval 120 \
  --poll-interval 10
```

### 情境 7：只查看鏈上合約資訊

```bash
python main.py fetch -a 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174 --chain polygon
```

### 情境 8：檢查 API Key 狀態

```bash
python main.py chains
```

### 情境 9：鏈上交易深度偵查（txscan）

```bash
# 監控 Polygon 上所有交易，自動深度掃描涉及的合約
python main.py watch -c polygon --modes txscan --no-ai

# 多鏈深度偵查
python main.py watch -c polygon,bsc,arbitrum --modes txscan

# 深度偵查 + 新部署監控
python main.py watch -c polygon --modes deploy,txscan --poll-interval 5
```

### 情境 10：白名單管理

```bash
# 查看目前白名單
python main.py whitelist list

# 手動將信任的合約加入白名單
python main.py whitelist add -a 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174 \
  --chain polygon --reason "USDC official"

# 按鏈篩選查看
python main.py whitelist list --chain polygon

# 移除白名單
python main.py whitelist remove -a 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174 --chain polygon

# 清空全部白名單
python main.py whitelist clear
```

### 情境 11：深度偵查 + 自動白名單

```bash
# 啟動深度偵查，掃描無問題的合約自動加入白名單
# 後續再遇到同一合約時自動跳過，節省掃描時間
python main.py watch -c polygon --modes txscan

# 停用自動白名單（每次都重新掃描）
python main.py watch -c polygon --modes txscan --no-auto-whitelist
```

### 情境 12：全方位監控（含深度偵查）

```bash
python main.py watch \
  -a 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174 \
  -c polygon,ethereum \
  -d ./contracts \
  --modes rescan,events,tx,deploy,txscan \
  --interval 120 \
  --poll-interval 10
```

---

## 支援的區塊鏈

| 鏈 | Chain ID | RPC |
|----|----------|-----|
| ethereum | 1 | https://eth.llamarpc.com |
| bsc | 56 | https://bsc-dataseed.binance.org |
| polygon | 137 | https://polygon-bor-rpc.publicnode.com |
| arbitrum | 42161 | https://arb1.arbitrum.io/rpc |
| optimism | 10 | https://mainnet.optimism.io |
| avalanche | 43114 | https://api.avax.network/ext/bc/C/rpc |
| base | 8453 | https://mainnet.base.org |

所有鏈使用 Etherscan V2 統一 API（`https://api.etherscan.io/v2/api`），透過 `chainid` 參數區分。

---

## 專案結構

```
contract-vuln-detector/
  main.py                    # CLI 入口
  config/
    settings.yaml            # 設定檔
  scanners/
    base_scanner.py          # 掃描器基礎類別 & Finding 資料結構
    pattern_scanner.py       # 正則模式掃描
    slither_scanner.py       # Slither 靜態分析
    mythril_scanner.py       # Mythril 符號執行
  fetchers/
    evm_fetcher.py           # EVM 合約原始碼抓取
    multi_chain.py           # 多鏈適配器
  analyzer/
    ai_analyzer.py           # AI 深度分析
    severity.py              # 嚴重性評分
    prompt_templates.py      # LLM 提示詞範本
  monitor/
    notifier.py              # 通知系統
    chain_monitor.py         # 鏈上監控
    file_monitor.py          # 本地檔案監控
    whitelist.py             # 白名單管理
  reports/
    report_generator.py      # 報告產生器
  examples/
    VulnerableBank.sol       # 測試用漏洞合約
```
