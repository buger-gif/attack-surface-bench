# superpowers

> 设计文档与规划笔记的工作目录，不随仓库发布。

本目录仅供开发过程中的设计讨论和迭代规划使用，内容不纳入 git 仓库。

如需查看项目设计决策，请参考根目录 `README.md` 的「设计决策记录」章节。

## 本次变更摘要（2026-07-15）

### v1.0 · 双网关 + Host 碰撞架构

核心改动：将单 nginx 网关拆为 **pub-gateway / priv-gateway** 双网关，引入 Host 碰撞机制测试 Agent 的子域名发现能力。

**架构变更：**
- pub-gateway（172.20.0.2）：仅路由 www / shop，宿主机 80 端口
- priv-gateway（172.20.0.3）：路由 admin / api / internal，宿主机 8081 端口
- DNS 仅解析 www / shop / admin；api / internal 必须通过 Host 碰撞发现
- www 根路径 `/` → 302 重定向到 `/shop`（浏览器友好）

**评测增强：**
- assertions.json v5.0：新增 `discovery_method`（dns / host_collision）和 `clue_sources` 字段
- S1/S2 场景更新：api / internal 标注为 Host 碰撞发现
- 新增 `alternate_url` / `priv_url`：vuln_verifier 和 functional test 支持 Host 碰撞验证
- S9–S16 普通场景：8 个安全端点用于误报率评测

**线索注入：**
- modern-app：JS 注释、X-Internal-Api 响应头、HTML 注释暴露内部域名线索
- admin-panel：X-Internal-Api 响应头、HTML 注释、SourceMap 泄露域名线索
- bff-gateway：404 错误页泄露 `api.target.bench` 域名

**基础设施：**
- docker-compose.yml v5.0：双 nginx 容器 + BIND9 DNS 更新
- 删除旧单网关 nginx.conf，新增 pub-gateway.conf / priv-gateway.conf
- named.conf v5.0：移除 api / internal / wildcard，admin 指向 priv-gateway

**测试覆盖：**
- functional pytest 68 个 HTTP 请求覆盖子域名可达性、HTML 交付、认证、脱敏等
- self-test 使用 pub:80 + priv:8081 双端口验证
- admin/api/internal 测试使用 priv_get/priv_post 方法通过 Host 碰撞验证

### v1.0-alpha · 2:8 比例重构 + FP 评测

- assertions.json 新增 S9–S16 共 8 个普通场景（68 个安全端点）
- 2:8 漏洞场景 vs 普通场景比例，用于评测误报率
- FP/TN 评测逻辑集成到 verifier
- internal-tools 增加 X-Admin-Token 认证头支持
