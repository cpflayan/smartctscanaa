## 1. 系统概述
该项目使用 Python 标准库 `logging` 模块作为唯一的日志框架。未引入第三方日志库（如 Loguru 或 structlog）。日志系统采用**集中式配置、分布式获取**的模式，通过 `logging.getLogger(__name__)` 在各模块中获取 logger 实例，并在入口文件 `main.py` 中进行全局基础配置。

## 2. 核心架构与配置
- **初始化位置**: `contract-vuln-detector/main.py`
  - 使用 `logging.basicConfig` 进行全局初始化。
  - **默认级别**: `INFO`。
  - **格式**: `%(asctime)s [%(levelname)s] %(name)s: %(message)s`。
  - **时间格式**: `%H:%M:%S`。
- **动态调整**: 
  - 通过 CLI 参数 `--verbose` (`-v`) 可将根 logger 级别动态调整为 `DEBUG`。
  - 代码示例: `logging.getLogger().setLevel(logging.DEBUG)`。

## 3. 日志使用规范
- **Logger 命名**: 遵循 Python 最佳实践，各模块使用 `logger = logging.getLogger(__name__)` 获取 logger。这使得日志输出中的 `%(name)s` 字段能准确反映模块路径（如 `scanners.slither_scanner`），便于追踪日志来源。
- **常用级别**:
  - `INFO`: 用于记录关键流程节点（如“开始 AI 深度分析”、“加载源码”）。
  - `WARNING`: 用于记录非致命异常或降级处理（如“AI 分析失败”、“Explorer API 错误”）。
  - `ERROR`: 用于记录导致功能失败的异常（如“LLM API 调用失败”、“Invalid address format”）。
  - `DEBUG`: 用于记录详细的解析过程或调试信息（如 Slither 结果解析失败）。

## 4. 关键文件分布
- `contract-vuln-detector/main.py`: 日志系统的唯一配置点。
- `contract-vuln-detector/analyzer/ai_analyzer.py`: 记录 AI 分析进度、LLM 调用状态及 JSON 解析警告。
- `contract-vuln-detector/fetchers/evm_fetcher.py`: 记录链上数据获取的网络请求状态及 API 响应错误。
- `contract-vuln-detector/scanners/slither_scanner.py`: 记录静态分析工具的安装状态、执行超时及 fallback 机制触发情况。

## 5. 开发者指南
1. **禁止直接打印**: 严禁在业务逻辑中使用 `print()` 输出调试信息，必须使用 `logger`。
2. **保持命名一致**: 始终使用 `__name__` 作为 logger 名称，不要硬编码字符串。
3. **敏感信息脱敏**: 在记录网络请求或 API 响应时（如 `evm_fetcher.py`），注意不要记录完整的 API Key 或敏感的合约内部状态，除非处于 DEBUG 模式且确有必要。
4. **异常日志**: 捕获异常时，应使用 `logger.error(f"描述: {e}")` 或 `logger.exception("描述")`（如果需要堆栈跟踪），目前项目中多采用前者。
