该智能合约漏洞检测器采用**基于标准库 `logging` 和 Python 原生异常机制**的错误处理策略。系统没有定义全局统一的错误码或自定义异常类体系，而是通过**分层捕获（Layered Catching）**、**优雅降级（Graceful Degradation）**和**结构化元数据返回**来管理运行时风险。

### 1. 核心策略与模式

*   **异常隔离与容错 (Fault Isolation)**：
    *   在并行扫描器执行中（`main.py`），每个扫描器的运行都被包裹在 `try...except Exception` 块中。单个扫描器（如 Slither 或 Mythril）的崩溃不会导致整个审计流程中断，而是记录错误日志并继续执行其他扫描器。
    *   AI 分析引擎（`ai_analyzer.py`）对每个漏洞点的分析也进行了独立隔离。如果某个点的 LLM 调用失败，系统会捕获异常并在该点的 `ai_analysis` 字段中填入错误信息，而不是终止整个批处理任务。

*   **优雅降级 (Graceful Degradation)**：
    *   **依赖缺失处理**：当外部工具（如 `slither-analyzer` 或 `mythril`）未安装时，扫描器不会直接抛出 `ImportError` 导致程序退出，而是捕获异常，记录错误日志，并返回空结果列表或切换到备用模式（如 `SlitherScanner` 的 `_fallback_scan` 尝试调用 CLI）。
    *   **API 失败处理**：链上数据获取失败时，`EVMFetcher` 捕获网络异常并返回 `(None, {"error": ...})` 元组，由上层逻辑决定是重试还是退出。

*   **错误传播约定**：
    *   **CLI 层**：`main.py` 作为入口点，负责捕获底层抛出的致命异常（如 `FileNotFoundError`, `RuntimeError`），将其转换为友好的 `click.echo` 错误消息并通过 `sys.exit(1)` 退出。
    *   **服务层**：底层模块（Fetchers, Scanners）倾向于**吞没异常**并返回“空结果”或“错误状态元数据”，而不是向上抛出异常。这种设计确保了工具的健壮性，但要求调用方必须检查返回值的有效性。

### 2. 关键文件与职责

| 文件路径 | 职责描述 |
| :--- | :--- |
| `contract-vuln-detector/main.py` | **全局异常边界**。处理 CLI 参数错误、文件加载异常，并隔离并行扫描器的运行时错误。 |
| `contract-vuln-detector/scanners/base_scanner.py` | 定义基础接口。虽未定义异常类，但规定了 `scan` 方法的契约，子类需遵循“失败返回空列表”的隐式约定。 |
| `contract-vuln-detector/scanners/slither_scanner.py` | **依赖容错典范**。捕获 `ImportError` 和 `SlitherException`，实现从 Python API 到 CLI 子进程的自动降级。 |
| `contract-vuln-detector/analyzer/ai_analyzer.py` | **LLM 交互容错**。处理 JSON 解析失败、API 超时和网络错误，确保部分分析失败不影响整体报告生成。 |
| `contract-vuln-detector/fetchers/evm_fetcher.py` | **网络错误标准化**。将 `requests.RequestException` 等网络错误统一转化为包含 `error` 键的元数据字典。 |

### 3. 开发者规范与建议

1.  **禁止静默失败**：所有 `except` 块必须伴随 `logger.error` 或 `logger.warning` 调用，以便用户排查问题（如缺少 API Key 或工具未安装）。
2.  **返回值检查**：调用 `fetch()` 或 `scan()` 后，必须检查返回的来源代码是否为 `None` 或 findings 列表是否为空，不能假设操作一定成功。
3.  **异常粒度**：在并行任务中，务必捕获最宽泛的 `Exception`，防止因未预见的异常（如内存溢出、断言失败）导致线程池死锁或主进程崩溃。
4.  **JSON 解析防御**：在与 LLM 或外部工具交互时，必须假设输出格式可能损坏，需实现多重解析策略（直接解析 -> 正则提取 -> 兜底原始文本）。
