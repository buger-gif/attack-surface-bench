# RSA 密钥对（靶场专用测试密钥）

本目录下的 RSA 密钥对是 **attack-surface-bench 靶场专用测试密钥**，为请求签名验证机制（v1.3 引入）单独生成。

| 文件 | 用途 |
|------|------|
| `rsa_private.pem` | PKCS#8 私钥，供 `src/secptest_benchmark/vuln_verifier.py` 自测时签名请求 |
| `rsa_public.pem` | 公钥，硬编码在 `admin-panel/app.py`、`bff-gateway/app.py` 中用于验证签名 |

## 为什么公开提交

- 这些密钥**不保护任何真实系统**——它们仅用于靶场内部的请求签名验证机制，离开本靶场无任何价值。
- 靶场的签名机制本身是 **测试 agent 能否发现/利用签名绕过漏洞** 的设计，不是真实安全边界。
- 公开私钥是**故意为之**：`vuln_verifier.py` 的 self-test 需要用私钥签名请求来验证靶场漏洞真实性，私钥必须随仓库分发以保证自测可复现。

## 不要用于生产

⚠️ **严禁将本密钥用于任何真实系统。** 这些密钥已公开，任何人都可获取，不具备任何保密性。请为生产环境单独生成密钥对。

## 重新生成（如需）

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa_private.pem
openssl rsa -pubout -in rsa_private.pem -out rsa_public.pem
# 同步更新 admin-panel/app.py、bff-gateway/app.py 中的 RSA_PUBLIC_KEY_PEM
# 同步更新 admin-panel/frontend/src/App.vue、bff-gateway/shop.html、account.html 中的 RSA_PRIVATE_KEY_PEM
```
