#!/usr/bin/env bash
# Cloud Agents - 挂载 GitHub 仓库启动脚本
# 仓库: cpflayan/smartctscanaa
#
# 使用前请设置环境变量:
#   export QODER_PAT="<你的Qoder Personal Access Token>"
#   export GITHUB_PAT="<你的GitHub Personal Access Token>"
#
# 用法:
#   bash scripts/cloud_agent_session.sh [会话标题]

# 依赖: curl, jq, python3（JSON格式化）

set -euo pipefail

SESSION_TITLE="${1:-Smart Contract Scanner Agent Session}"
GITHUB_REPO_URL="https://github.com/cpflayan/smartctscanaa"
MOUNT_PATH="/app/smartctscanaa"
QODER_API="https://api.qoder.com/api/v1/cloud"

# 校验环境变量
for var in QODER_PAT GITHUB_PAT; do
  if [ -z "${!var:-}" ]; then
    echo "错误: 请先设置 $var 环境变量"
    echo "  export $var=\"<你的 $var>\""
    exit 1
  fi
done

# 自动获取 environment_id（取第一个）
echo "正在获取环境 ID..."
ENV_ID=$(curl -s "$QODER_API/environments" \
  -H "Authorization: Bearer $QODER_PAT" | python3 -c "import sys,json; print(json.load(sys.stdin)['data'][0]['id'])")
echo "  环境 ID: $ENV_ID"

# 自动获取 agent_id（取第一个）
echo "正在获取 Agent ID..."
AGENT_ID=$(curl -s "$QODER_API/agents" \
  -H "Authorization: Bearer $QODER_PAT" | python3 -c "import sys,json; print(json.load(sys.stdin)['data'][0]['id'])")
echo "  Agent ID: $AGENT_ID"

echo ""
echo "正在创建 Cloud Agent Session..."
echo "  仓库: $GITHUB_REPO_URL"
echo "  挂载路径: $MOUNT_PATH"
echo "  标题: $SESSION_TITLE"
echo ""

RESPONSE=$(curl -s -X POST "$QODER_API/sessions" \
  -H "Authorization: Bearer $QODER_PAT" \
  -H "Content-Type: application/json" \
  -d "{
    \"agent\": {\"id\": \"$AGENT_ID\", \"type\": \"agent\", \"version\": 1},
    \"environment_id\": \"$ENV_ID\",
    \"title\": \"$SESSION_TITLE\",
    \"resources\": [
      {
        \"type\": \"github_repository\",
        \"url\": \"$GITHUB_REPO_URL\",
        \"mount_path\": \"$MOUNT_PATH\",
        \"authorization_token\": \"$GITHUB_PAT\"
      }
    ]
  }")

echo "API 响应:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"

# 提取 session ID
SESSION_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")
if [ -n "$SESSION_ID" ]; then
  echo ""
  echo "Session 已创建！ID: $SESSION_ID"
  echo "发送消息:"
  echo "  curl -s -X POST \"$QODER_API/sessions/$SESSION_ID/events\" \\"
  echo "    -H \"Authorization: Bearer \\\$QODER_PAT\" \\"
  echo "    -H \"Content-Type: application/json\" \\"
  echo '    -d '"'"'{"type":"user.message","content":"你的指令"}'"'"''
fi
