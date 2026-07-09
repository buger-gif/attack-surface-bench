# 如何适配你的安全测试 Agent

本指南说明如何让你的安全测试 Agent 接入 secptest-benchmark 评测协议。

---

## 适配三步

### 第 1 步：输出 SARIF 2.1.0

Agent 必须输出 SARIF 2.1.0 JSON 格式的 findings。最小可行 SARIF 文件：

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Sarif-2.1.0.json",
  "runs": [{
    "tool": {"driver": {"name": "your-agent-name", "version": "1.0.0"}},
    "results": [...]
  }]
}
```

### 第 2 步：填充扩展字段

benchmark verifier 通过 `properties` 扩展字段将 findings 与断言匹配。最重要的字段是 `evidence.request_url`——没有它，verifier 无法确认 findings，会标为 `weak` confidence。

扩展字段完整表见下方 [SARIF 扩展字段](#sarif-扩展字段) 章节。

### 第 3 步：接入靶场网络

Agent 必须能解析 `*.target.com` 并访问靶场服务。参见 [Docker 网络接入](#docker-网络接入) 章节。

---

## SARIF 扩展字段

每个 result 的 `properties` 对象下定义以下字段：

| 字段 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `category` | string | 推荐 | 漏洞分类关键词，用于 URL 无法匹配时的 category 匹配。示例：`jwt_none`、`nosqli_ne`、`ssrf`、`prototype_pollution`、`access_control` |
| `evidence.request_url` | string | **必需** | 实际测试的 URL，这是 URL 匹配的主信号 |
| `evidence.response_status` | int | 推荐 | HTTP 响应状态码，用于 confidence 评估 |
| `evidence.response_body_snippet` | string | 推荐 | 响应体前 ~200 字符，支持证据审查 |
| `evidence.request_method` | string | 推荐 | HTTP 方法（GET/POST/PUT/DELETE） |
| `severity` | string | 推荐 | 严重级别：`critical` / `high` / `medium` / `low` |
| `detection_trace` | string | 可选 | 发现路径描述（调试用，不影响匹配） |

### category 值参考

以下 category 值与断言场景对应，使用这些值可提高匹配精度：

| category 值 | 对应场景 | 说明 |
|-------------|---------|------|
| `jwt_none` | S4 modern_vulns | JWT alg=none 绕过 |
| `jwt_weak` | S4 modern_vulns | JWT 弱密钥 |
| `jwt_expire_bypass` | S4 modern_vulns | JWT 过期绕过 |
| `nosqli_ne` | S4 modern_vulns | NoSQL $ne 注入 |
| `nosqli_gt` | S4 modern_vulns | NoSQL $gt 注入 |
| `prototype_pollution` | S4 modern_vulns | 原型链污染 |
| `mass_assignment` | S4 modern_vulns | Mass Assignment |
| `excessive_data` | S4 modern_vulns | 过度数据暴露 |
| `cors_wildcard` | S4 modern_vulns | CORS 通配符 |
| `ssrf` | S4 modern_vulns | SSRF |
| `integer_overflow` | S4 modern_vulns | 整数溢出 |
| `open_redirect` | S4 modern_vulns | 开放重定向 |
| `graphql_introspection` | S4 modern_vulns | GraphQL 内省 |
| `access_control` | S2 multi_entry_bypass | 权限绕过 |
| `info_leak` | S5 info_leak | 信息泄露 |
| `hidden_param` | S3 hidden_param_detection | 隐藏参数 |

### 匹配逻辑

verifier 使用四路宽松匹配策略，按优先级排序：

1. **ruleId 精确匹配** — `finding.ruleId == assertion.id`（最可靠）
2. **url_pattern 正则匹配** — `assertion.url_pattern` 正则匹配 `finding.uri`
3. **url_path 子串匹配** — `assertion.url_path` 是 `finding.uri` 的子串
4. **category 关键词匹配** — `finding.category` 与 `assertion.category` 匹配（不区分大小写）

每条 finding 最多匹配一条断言，每条断言最多匹配一次。未匹配的 findings 记入"额外发现"。

### Confidence 评估

| 级别 | 条件 | 含义 |
|------|------|------|
| **confirmed** | 有 `request_url` + `response_status` | 有完整 HTTP 证据 |
| **unconfirmed** | 有描述但缺关键证据字段 | 需人工复核 |
| **weak** | 无证据也无 URI | 可信度低 |

---

## Docker 网络接入

靶场使用自定义 Docker 网络（`bm-net`，子网 `172.20.0.0/24`）。Agent 容器必须加入该网络并使用靶场 DNS 解析器。

### Docker 容器方式（推荐）

```bash
docker run \
  --dns 172.20.0.53 \
  --network secptest-bm_bm-net \
  your-agent-image
```

DNS 服务器 172.20.0.53 解析：
- `www.target.com` → Nginx 网关 → modern-app (Node.js + MongoDB)
- `admin.target.com` → Nginx 网关 → admin-panel (Flask + 隐藏参数)
- `api.target.com` → Nginx 网关 → admin-panel（权限绕过路由）
- `shop.target.com` → Nginx 网关 → bff-gateway (BFF 聚合层)
- `internal.target.com` → Nginx 网关 → internal-tools (信息泄露)

> 注意：Docker Compose 创建的网络名带项目前缀，完整名称为 `secptest-bm_bm-net`。

### secptest 平台接入

在 secptest `.env` 中添加：

```env
BENCHMARK_NETWORK=bm-net
BENCHMARK_DNS=172.20.0.53
BENCHMARK_DOMAINS=["target.com"]
```

Worker 容器自动加入双网络（secptest-net + bm-net）+ DNS 注入。无需手动修改 `container_templates.py`。

### 本地测试（/etc/hosts）

非 Docker 环境的 Agent：

```bash
# 添加到 /etc/hosts（映射到宿主机 gateway 端口 8080）
echo "127.0.0.1 www.target.com admin.target.com api.target.com shop.target.com internal.target.com" | sudo tee -a /etc/hosts
```

然后通过宿主机映射端口访问服务（参见 `targets/docker-compose.yml` 的 ports 配置）。

---

## 适配器示例

`CONTRIBUTING_adapter_examples/` 目录包含可直接使用的适配器：

| 文件 | 说明 |
|------|------|
| `nuclei_to_sarif.py` | 将 Nuclei JSON 输出转换为 SARIF 格式 |
| `sarif_schema_reference.md` | SARIF 2.1.0 扩展字段完整规范 + 示例 |

### 编写自定义适配器

最小适配器将 Agent 的原生输出格式转换为 SARIF：

```python
import json
from pathlib import Path

def your_agent_to_sarif(agent_output: dict) -> dict:
    """将 Agent 输出转换为 SARIF 2.1.0 格式"""
    results = []
    for finding in agent_output["findings"]:
        results.append({
            "ruleId": finding["id"],
            "level": "error" if finding["severity"] in ("critical", "high") else "warning",
            "message": {"text": finding["description"]},
            "locations": [{"physicalLocation": {"uri": finding["url"]}}],
            "properties": {
                "category": finding.get("category", ""),
                "severity": finding.get("severity", "medium"),
                "evidence": {
                    "request_url": finding["url"],
                    "response_status": finding.get("status_code"),
                    "response_body_snippet": finding.get("body", "")[:200],
                    "request_method": finding.get("method", "GET"),
                },
            },
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "your-agent", "version": "1.0.0"}},
            "results": results,
        }],
    }
```

---

## 运行评测流程

```bash
# 完整流程
make up                                    # 启动靶场
# ... 运行你的 Agent，输出 SARIF ...
uv run benchmark verify findings.sarif.json    # 验证
uv run benchmark report report.json            # 查看报告

# 或使用 make
make verify FINDINGS=findings.sarif.json OUTPUT=report.json
make report INPUT=report.json OUTPUT=report.json

# 自测靶场漏洞真实性
uv run benchmark self-test
```

---

## 添加新场景

如需扩展靶场攻击面：

1. 在 `targets/docker-compose.yml` 中添加新的漏洞服务容器
2. 在 `assertions.json` 中添加新场景 ID 和断言定义
3. 在 `targets/dns/db.target.com` 和 `targets/dns/named.conf` 中添加新子域名 DNS 记录
4. 在 `targets/gateway/nginx.conf` 中添加 Nginx 路由配置
5. 在 `src/secptest_benchmark/vuln_verifier.py` 中添加对应的 HTTP 测试用例
6. 运行 `uv run pytest tests/ -v` 确认无破坏

---

## 常见问题

### Q：我的 Agent 输出不是 SARIF 格式怎么办？

使用适配器转换。参见上方"编写自定义适配器"章节，或使用 `CONTRIBUTING_adapter_examples/nuclei_to_sarif.py` 作为参考模板。

### Q：完全标准 SARIF（无扩展字段）能验证吗？

可以。verifier 靠 `locations.uri` + `message.text` 正则匹配兜底。但 confidence 会降为 `unconfirmed` 或 `weak`，建议至少填充 `evidence.request_url`。

### Q：Agent 发现了断言没列的漏洞怎么办？

这是"额外发现"，verifier 会记入 `extra` 字段——**是亮点不是噪音**。断言只定义预期攻击面，Agent 可以发现更多。

### Q：`bm-net` 网络名为什么有前缀？

Docker Compose 使用项目名作为网络前缀。`-p secptest-bm` 参数使完整网络名为 `secptest-bm_bm-net`。使用 `docker network ls` 查看实际名称。

### Q：DNS 解析 172.20.0.2 和 172.20.0.53 的区别？

172.20.0.53 是 BIND9 DNS 服务器，负责解析 `*.target.com`。172.20.0.2 是 Nginx 网关。Agent 的 `--dns` 应指向 172.20.0.53（DNS 服务器），而非 172.20.0.2（网关）。
