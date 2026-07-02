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

set -euo pipefail

SESSION_TITLE="${1:-Smart Contract Scanner Agent Session}"
GITHUB_REPO_URL="https://github.com/cpflayan/smartctscanaa"
MOUNT_PATH="/app/smartctscanaa"

if [ -z "${QODER_PAT:-}" ]; then
  echo "错误: 请先设置 QODER_PAT 环境变量"
  echo "  export QODER_PAT=\"<你的Qoder PAT>\""
  exit 1
fi

if [ -z "${GITHUB_PAT:-}" ]; then
  echo "错误: 请先设置 GITHUB_PAT 环境变量"
  echo "  export GITHUB_PAT=\"<你的GitHub PAT>\""
  exit 1
fi

echo "正在创建 Cloud Agent Session..."
echo "  仓库: $GITHUB_REPO_URL"
echo "  挂载路径: $MOUNT_PATH"
echo "  标题: $SESSION_TITLE"

RESPONSE=$(curl -s -X POST https://api.qoder.com/api/v1/cloud/sessions \
  -H "Authorization: Bearer $QODER_PAT" \
  -H "Content-Type: application/json" \
  -d "{
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

echo ""
echo "API 响应:"
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
