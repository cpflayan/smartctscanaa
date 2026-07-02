该项目采用标准的 Python `requirements.txt` 进行依赖管理，未使用虚拟环境管理工具（如 Poetry 或 Pipenv）或锁定文件（如 `requirements.lock`）。

### 1. 依赖声明系统
- **管理工具**: 使用基础的 `pip` 包管理器。
- **清单文件**: `contract-vuln-detector/requirements.txt` 是唯一的依赖声明文件。
- **版本策略**: 采用最小版本约束（例如 `slither-analyzer>=0.10.0`），允许自动获取兼容的更新版本，但未固定具体版本号以确保构建的可复现性。

### 2. 核心依赖分类
- **静态分析引擎**: `slither-analyzer`, `mythril`（作为外部扫描器集成）。
- **区块链交互**: `web3` (用于链上数据获取)。
- **AI 集成**: `openai` (用于深度漏洞分析)。
- **工具库**: `click` (CLI), `PyYAML` (配置解析), `rich` (终端输出), `aiohttp` (异步请求)。

### 3. 配置与密钥管理
- **配置文件**: `config/settings.yaml` 集中管理扫描器、链信息和 LLM 参数。
- **敏感信息**: API Key（如 OpenAI, Etherscan）通过环境变量占位符（如 `${OPENAI_API_KEY}`）在配置文件中引用，避免硬编码。

### 4. 开发者规范
- **安装方式**: 运行 `pip install -r requirements.txt` 安装所有依赖。
- **环境隔离**: 建议在虚拟环境（venv/conda）中运行以避免全局污染。
- **配置加载**: 应用启动时通过 `yaml.safe_load` 读取 `settings.yaml`，并自动替换环境变量。