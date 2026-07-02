## 1. 核心系统与架构
该项目采用**静态 YAML 文件为主、环境变量注入为辅、CLI 参数动态覆盖**的混合配置策略。核心逻辑集中在 `main.py` 的 `load_config` 函数中，通过 `PyYAML` 库解析 `config/settings.yaml`。配置数据在应用启动时一次性加载，并通过 Click 框架的 `ctx.obj` 上下文对象在整个 CLI 生命周期中传递。

### 关键设计模式：
- **集中式配置源**：所有模块（扫描器、AI 分析器、多链获取器）均从同一个字典对象中读取各自的配置片段，避免了配置分散。
- **懒加载与环境变量解析**：敏感信息（如 API Key）不在 YAML 中硬编码，而是使用 `${ENV_VAR}` 占位符。代码在初始化具体组件（如 `MultiChainFetcher` 或 `AIAnalyzer`）时，通过 `os.environ.get()` 动态解析这些占位符。
- **默认值回退机制**：在 `multi_chain.py` 等模块中，如果 YAML 未提供特定链的配置，系统会自动回退到代码内部定义的 `DEFAULT_CHAINS` 常量，确保了系统的健壮性。

## 2. 关键配置文件与逻辑
- **`contract-vuln-detector/config/settings.yaml`**：唯一的静态配置文件。定义了 LLM 提供商（OpenAI/Ollama/Azure）、扫描器超时时间、启用的检测器列表、多链 RPC/Explorer 地址以及报告输出格式。
- **`contract-vuln-detector/main.py`**：配置加载入口。`load_config()` 函数负责读取 YAML；`cli` 组命令通过 `--config` 选项允许用户指定自定义配置文件路径。
- **`contract-vuln-detector/fetchers/multi_chain.py`**：展示了配置的消费模式。它接收来自 YAML 的 `chain_config` 字典，并结合 `DEFAULT_CHAINS` 和 `os.environ` 来构建最终的链访问凭证。
- **`contract-vuln-detector/analyzer/ai_analyzer.py`**：处理 LLM 相关的配置。它在初始化时解析 `api_key` 字段，支持直接传入密钥或引用环境变量名。

## 3. 开发者规范与约定
1. **敏感信息管理**：严禁在 `settings.yaml` 中明文存储 API Key。必须使用 `${VAR_NAME}` 语法，并在运行前通过 `export` 设置对应的环境变量。
2. **配置扩展**：若需新增功能配置，应在 `settings.yaml` 中添加对应的键值对，并在相关类的 `__init__` 方法中通过 `config.get("key", default)` 方式安全获取，确保向后兼容。
3. **CLI 优先级**：目前 CLI 参数（如 `--output`）主要在运行时直接传递给函数，部分覆盖了 YAML 中的默认行为。开发新功能时，应遵循“CLI 参数 > YAML 配置 > 代码默认值”的优先级原则。
4. **链配置同步**：新增支持的区块链时，需同时在 `settings.yaml` 的 `chains` 节点和 `multi_chain.py` 的 `DEFAULT_CHAINS` 中保持结构一致，以确保离线默认配置的可用性。