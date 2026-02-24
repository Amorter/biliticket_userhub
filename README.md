# BiliTicket UserHub

一个面向账号中心（CIAM）的 Go 后端服务，提供统一登录、统一身份绑定、OIDC Provider、社交登录（GitHub/Google）和 Passkey（WebAuthn）能力。

项目目标是同时支持云原生和非云原生部署：
- 持久化数据用 PostgreSQL
- 临时状态通过 `StateStore` 抽象，可选 Redis 或内存
- 可部署到阿里云函数计算 FC（Custom Runtime）或常规容器/主机

## 功能总览

| 能力 | 当前状态 | 说明 |
| --- | --- | --- |
| 用户注册 | 已支持 | 统一入口 `/api/v1/auth/register`，支持邀请码开关 |
| 用户登录（密码） | 已支持 | `/api/v1/auth/login`，密码走 bcrypt 校验 |
| Refresh Token 轮转 | 已支持 | 刷新时旧 token 立即失效（防重放） |
| 身份绑定/解绑 | 已支持 | 支持 password/github/google/passkey 身份模型 |
| OAuth2 社交登录 | 已支持 | GitHub / Google，基于 state 防 CSRF |
| Passkey 登录/注册 | 已支持 | Discoverable Login，挑战信息入 StateStore |
| OIDC Provider | 已支持 | 基于 `zitadel/oidc`，提供 `/oidc/*` 标准端点 |
| OIDC Client 管理 API | 未提供 | 当前需直接写数据库 `oidc_clients` |

## 目录结构

```text
cmd/main.go                     # 服务入口
internal/config                 # 配置加载 + PG/Redis 初始化
internal/model                  # GORM 模型（users / user_identities / oidc_clients / invite_codes）
internal/repository             # 数据访问层 + StateStore 抽象
internal/service                # 业务逻辑（auth / identity / oauth2 / webauthn / invite）
internal/handler                # HTTP 接口层 + middleware
internal/oidc                   # OIDC provider storage/client/auth request 实现
pkg/jwt                         # JWT 生成与校验
pkg/crypto                      # 密码哈希与随机串
pkg/response                    # 统一 API 响应结构
config.yaml                     # 默认配置
```

## 快速开始（本地开发）

### 1. 运行依赖

需要：
- Go `1.25+`
- PostgreSQL `14+`
- Redis `6+`（如果使用 `state.backend=redis`）

你也可以用 Docker 快速起依赖：

```bash
docker run -d --name userhub-pg \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=biliticket_userhub \
  -p 5432:5432 postgres:16

docker run -d --name userhub-redis \
  -p 6379:6379 redis:7
```

### 2. 初始化 PostgreSQL 扩展

模型里 UUID 默认值使用了 `gen_random_uuid()`，请先启用 `pgcrypto`：

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
```

### 3. 配置 `config.yaml`

最低要确认这几项：
- `database.postgres.*`
- `state.backend`（`redis` 或 `memory`）
- `jwt.signing_key`（生产环境必须替换）
- `oidc.issuer` 与 `oidc.login_url`

环境变量可覆盖 YAML（Viper 自动映射 `.` -> `_`），例如：

```bash
export DATABASE_POSTGRES_HOST=127.0.0.1
export DATABASE_POSTGRES_PASSWORD=postgres
export STATE_BACKEND=memory
```

### 4. 启动服务

```bash
go run ./cmd/main.go
```

### 5. 健康检查

```bash
curl http://127.0.0.1:8080/healthz
```

期望响应：

```json
{"status":"ok"}
```

## 配置说明（高频项）

| 配置键 | 作用 | 建议 |
| --- | --- | --- |
| `invite.enabled` | 是否开启邀请码注册 | 生产建议开启 |
| `admin.user_ids` | 管理员 UUID 白名单 | 至少配置 1 个管理员 |
| `state.backend` | 临时状态后端 | 单机开发可 `memory`，生产建议 `redis` |
| `oidc.crypto_key` | OIDC 加解密种子 | 使用高强度随机字符串 |
| `oauth2.github/google` | 社交登录配置 | 不配置则对应 provider 不可用 |
| `webauthn.rp_id/rp_origins` | Passkey relying party 参数 | 必须和前端域名一致 |

## 响应与鉴权约定

### 统一响应格式

成功：

```json
{"code":0,"message":"ok","data":{}}
```

失败：

```json
{"code":401,"message":"invalid or expired token"}
```

### Bearer Token

受保护接口需传：

```text
Authorization: Bearer <access_token>
```

## 使用手册

### 1) 用户注册与密码登录

注册（默认开启邀请码时需传 `invite_code`）：

```bash
curl -X POST http://127.0.0.1:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{
    "identity_type": "password",
    "identifier": "alice@example.com",
    "credential_data": {"password": "S3cret1234"},
    "invite_code": "abcd1234efgh5678"
  }'
```

登录：

```bash
curl -X POST http://127.0.0.1:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{
    "identity_type": "password",
    "identifier": "alice@example.com",
    "credential_data": {"password": "S3cret1234"}
  }'
```

刷新令牌：

```bash
curl -X POST http://127.0.0.1:8080/api/v1/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<refresh_token>"}'
```

登出（撤销 refresh token）：

```bash
curl -X POST http://127.0.0.1:8080/api/v1/auth/logout \
  -H 'Authorization: Bearer <access_token>' \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<refresh_token>"}'
```

### 2) 身份绑定与解绑

绑定新身份（示例：绑定另一个密码身份）：

```bash
curl -X POST http://127.0.0.1:8080/api/v1/identities/bind \
  -H 'Authorization: Bearer <access_token>' \
  -H 'Content-Type: application/json' \
  -d '{
    "identity_type": "password",
    "identifier": "alice2@example.com",
    "credential_data": {"password": "AnotherPass123"}
  }'
```

查看身份列表：

```bash
curl http://127.0.0.1:8080/api/v1/identities \
  -H 'Authorization: Bearer <access_token>'
```

解绑身份：

```bash
curl -X DELETE http://127.0.0.1:8080/api/v1/identities/<identity_id> \
  -H 'Authorization: Bearer <access_token>'
```

说明：系统不允许解绑最后一个身份凭证。

### 3) OAuth2 社交登录（GitHub/Google）

发起授权（会 302 跳转到 provider）：

```bash
curl -i 'http://127.0.0.1:8080/api/v1/auth/oauth2/github/authorize'
```

回调地址由 `oauth2.<provider>.redirect_url` 决定，成功后返回本系统 token。

重要行为：
- 仅对“已绑定该 provider 身份”的用户签发 token
- 不会因为邮箱同名而自动绑定或自动建号

### 4) Passkey（WebAuthn）

注册流程（需先登录获取 access token）：
1. `POST /api/v1/auth/passkey/register/begin`，拿到 `options` + `session_id`
2. 前端调用 `navigator.credentials.create({ publicKey: options })`
3. 将浏览器返回的 attestation JSON 提交到：
`POST /api/v1/auth/passkey/register/finish?session_id=<session_id>`

登录流程：
1. `POST /api/v1/auth/passkey/login/begin`，拿到 `options` + `session_id`
2. 前端调用 `navigator.credentials.get({ publicKey: options })`
3. 提交 assertion 到：
`POST /api/v1/auth/passkey/login/finish?session_id=<session_id>`

说明：`finish` 接口读取的是 WebAuthn 标准请求体，`session_id` 在 query 中传递。

### 5) 管理员接口（邀请码）

创建邀请码：

```bash
curl -X POST http://127.0.0.1:8080/api/v1/admin/invite-codes \
  -H 'Authorization: Bearer <admin_access_token>' \
  -H 'Content-Type: application/json' \
  -d '{"max_uses": 10}'
```

查看邀请码：

```bash
curl http://127.0.0.1:8080/api/v1/admin/invite-codes \
  -H 'Authorization: Bearer <admin_access_token>'
```

## OIDC 接入指南（给业务应用）

### 1) 先创建 OIDC Client（当前通过 SQL）

```sql
INSERT INTO oidc_clients (
  client_id,
  client_secret,
  name,
  redirect_uris,
  allowed_scopes,
  is_first_party,
  created_at,
  updated_at
) VALUES (
  'demo-client',
  'demo-client-secret',
  'Demo App',
  '["http://localhost:3000/oidc/callback"]'::jsonb,
  '["openid","profile","email","offline_access"]'::jsonb,
  true,
  NOW(),
  NOW()
);
```

### 2) 发起授权请求

```text
GET /oidc/authorize?
  client_id=demo-client&
  redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Foidc%2Fcallback&
  response_type=code&
  scope=openid%20profile%20email%20offline_access&
  state=xyz&
  nonce=n-123&
  code_challenge=<pkce_challenge>&
  code_challenge_method=S256
```

### 3) 用户登录完成后，调用登录完成接口

OIDC Provider 会把浏览器重定向到 `oidc.login_url`（模板里带 `auth_request_id`）。
前端在用户完成本系统登录后，调用：

```bash
curl -X POST http://127.0.0.1:8080/api/v1/oidc/login/complete \
  -H 'Authorization: Bearer <access_token>' \
  -H 'Content-Type: application/json' \
  -d '{"auth_request_id":"<auth_request_id>"}'
```

接口返回 `callback_url`，前端把浏览器重定向过去。

### 4) 客户端用授权码换 Token

```bash
curl -X POST http://127.0.0.1:8080/oidc/token \
  -u demo-client:demo-client-secret \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code&code=<code>&redirect_uri=http://localhost:3000/oidc/callback&code_verifier=<pkce_verifier>'
```

### 5) 获取用户信息

```bash
curl http://127.0.0.1:8080/oidc/userinfo \
  -H 'Authorization: Bearer <access_token>'
```

发现文档地址：

```text
GET /oidc/.well-known/openid-configuration
GET /oidc/keys
```

## 开发说明

### 启动顺序（`cmd/main.go`）

1. 读取配置
2. 初始化日志
3. 连接 PostgreSQL
4. 自动迁移（可配置）
5. 初始化 StateStore（Redis/Memory）
6. 初始化 Repository / Service / Handler
7. 初始化 OIDC Provider
8. 启动 Gin + 优雅退出

### StateStore 键规范

| 用途 | Key 格式 | TTL |
| --- | --- | --- |
| Refresh Token 状态 | `refresh_token:{jti}` | refresh token 过期时间 |
| OAuth2 state | `oauth2_state:{token}` | 10 分钟 |
| WebAuthn 注册会话 | `webauthn_reg:{sessionID}` | 5 分钟 |
| WebAuthn 登录会话 | `webauthn_login:{sessionID}` | 5 分钟 |
| OIDC auth request | `oidc_auth_req:{id}` | 10 分钟 |
| OIDC auth code | `oidc_code:{code}` | 10 分钟 |
| OIDC access token metadata | `oidc_access:{tokenID}` | `access_token_ttl` |
| OIDC refresh token metadata | `oidc_refresh:{token}` | `refresh_token_ttl` |

## 已知注意事项

1. 邀请码引导启动：`invite.enabled=true` 时，建议先临时关闭邀请码创建首个管理员，再开启邀请码。
2. OIDC 签名密钥当前为进程启动时临时生成，重启后历史 token/JWKS 不可延续，生产建议改为持久化密钥。
3. `oidc_clients.client_secret` 当前是明文比对，生产建议改为哈希存储。
4. OAuth2 登录和 OAuth2 绑定共用 `oauth2.<provider>.redirect_url`，如果要同时稳定支持两条流程，建议后续拆分配置或统一回调入口处理不同 `state.purpose`。

## 与 FC 部署的关系

该项目符合 FC Custom Runtime 常见要求：
- 标准 HTTP 服务 + 优雅退出
- 状态外置（Redis）
- 配置可走环境变量覆盖

部署到 FC 时，推荐：
- `state.backend=redis`
- PostgreSQL 与 Redis 使用托管服务
- 使用安全的 `jwt.signing_key` 和 `oidc.crypto_key`
