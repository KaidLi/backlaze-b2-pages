# B2 Pages Proxy — S3 兼容私有存储代理

这是 [Starhes/backlaze-b2-pages](https://github.com/Starhes/backlaze-b2-pages) 的安全修复分支。部署在 Cloudflare Pages Functions 上，让 Memos、Rclone 等 S3 客户端通过 Cloudflare 读写 Backblaze B2 私有桶。

```text
Memos / S3 客户端 ←→ Cloudflare Pages Functions ←→ Backblaze B2 私有桶
```

B2 到 Cloudflare 的流量可利用带宽联盟。该项目不会改变 B2 存储额度、Cloudflare Functions 请求额度，或者 Memos 所在服务器的流量计费。

## 已修复的问题

原实现只比较 Access Key ID，没有验证客户端签名；鉴权错误还会返回预期的 Key ID。当前实现：

- 用 Web Crypto 完整验证 AWS Signature V4，支持 Authorization 请求头与预签名 URL。
- 校验原始域名、方法、路径、查询参数、SignedHeaders、凭据范围和 HMAC；拒绝重复查询参数或混用的认证参数。
- 请求头签名最多允许过去 15 分钟、未来 5 分钟的时钟偏差；预签名 URL 按 `X-Amz-Expires` 到期，最长 7 天。
- 包括 GET、HEAD 在内的所有文件请求都必须先通过鉴权；鉴权失败不会请求 B2。
- 代理自身的错误响应及应用日志不再返回密钥标识、签名 URL、请求凭据或异常堆栈。
- 根据 B2 Endpoint 推导正确的签名 Region，保留 multipart 查询参数、内容哈希和文件元数据。
- 默认禁用共享缓存，响应使用 `private, no-store`。带宽联盟免 B2 出站费用不依赖缓存命中。

这是单租户代理：持有配置密钥的客户端拥有该 B2 应用密钥对应的权限。它不负责校验 Memos 的用户登录或单条笔记权限；这部分继续由 Memos 处理。

## 部署到 Cloudflare Pages

1. Fork 此仓库，在 Cloudflare Pages 创建项目并连接自己的仓库。
2. Framework preset 选择 `None`，Build command 为 `npm run build`，Output directory 为 `public`。
3. 设置构建用 Node.js 版本为 **24**，例如环境变量 `NODE_VERSION=24`。
4. 在 Pages 项目的运行环境变量中填写下表四项。生产环境与预览环境分别配置，不要把密钥写入源码或提交到 Git。
5. 重新部署，使运行环境变量生效。

也可以通过已登录的 Wrangler 直接部署：`npm run deploy -- --project-name <项目名> --branch main`。本仓库的 Wrangler 配置只用于本地开发，生产变量由 Cloudflare Dashboard 管理。直接上传创建的 Pages 项目没有连接 GitHub，后续更新需要再次运行部署命令；后台保存变量后也需要创建新部署。

| 变量 | 内容 |
| --- | --- |
| `B2_BUCKET_NAME` | B2 实际私有桶名称 |
| `B2_ENDPOINT` | 桶页面显示的 Endpoint，例如 `s3.us-west-004.backblazeb2.com`；也接受带 `https://` 的形式 |
| `B2_ACCESS_KEY_ID` | 仅允许访问这个桶的专用 Application Key ID |
| `B2_SECRET_ACCESS_KEY` | 对应的 Application Key，使用 Cloudflare 加密 Secret 保存 |

不要使用 B2 主密钥。只授予客户端确实需要的列出、读取、上传和删除文件权限。桶应保持 **Private**；不要为了部署代理将它改为 Public 或提升付费额度。

## Memos 配置

在“设置 → 存储”中选择 S3 兼容存储：

| 字段 | 填写内容 |
| --- | --- |
| Endpoint | `https://你的项目.pages.dev`，或绑定到此 Pages 项目的 HTTPS 域名 |
| Region | B2 Endpoint 中的地区，例如 `us-west-004` |
| Bucket | 与 `B2_BUCKET_NAME` 相同的实际桶名称 |
| Access Key / Secret Key | 与 Pages 配置一致的专用应用密钥 |
| 路径式访问（Path-style） | **开启** |
| 跳过 TLS 验证 | **关闭** |

使用实际桶名时，客户端路径 `/桶名/文件` 直接转发到该桶。为兼容原项目，其他首段会作为对象目录前缀保留，例如 `/notes/file` 转发为 `/实际桶名/notes/file`。

Memos 0.31 通过自己的文件接口验证笔记权限并转发 S3 文件。附件仍可能经过 Memos 服务器，但 B2 向此 Pages 代理返回数据的链路经过 Cloudflare。切换 Memos 默认存储只影响新上传文件；旧附件及原存储配置需要保留。

## 其他 S3 客户端

Rclone 示例：

```ini
[b2-pages]
type = s3
provider = Other
access_key_id = <专用应用密钥 ID>
secret_access_key = <专用应用密钥>
endpoint = https://your-project.pages.dev
region = us-west-004
force_path_style = true
```

AWS CLI 示例，凭据通过命名 profile 或环境变量提供：

```sh
aws s3 cp test.jpg s3://<实际桶名>/test.jpg \
  --region us-west-004 \
  --endpoint-url https://your-project.pages.dev
```

## 兼容范围与限制

- 支持普通 GET、HEAD、PUT、POST、DELETE 以及标准 multipart API。Cloudflare 各套餐的单次请求大小与 Functions 免费额度仍适用。
- 支持 SHA-256 内容哈希与 `UNSIGNED-PAYLOAD`。已签名的内容哈希会原样传给 B2，由 B2 校验流式文件内容；代理不会把有哈希的请求悄悄降级为无哈希。
- AWS 逐块签名的 `STREAMING-*` 传输格式和临时 Session Token 不受支持，遇到会拒绝；可以使用普通 multipart 上传。
- 客户端需准确设置系统时间。不要让中间代理更改已签名的域名、路径或头部；变动后必须重新签名，不能跳过验证。
- 不提供匿名外链或跨域浏览器直传。Memos 等服务端 S3 客户端不需要浏览器 CORS。
- 本分支的自动化测试使用虚拟凭据和模拟 B2 响应，不连接真实账户。首次上线仍需用小文件实测上传、下载、删除，并确认错误签名和过期 URL 被拒绝。
- B2 不是数据备份的替代品。旧版本、隐藏文件、其他桶会一起占用账号容量；保持免费账号限制，并另行保存数据库和附件备份。

## 本地检查

需要 Node.js 24 或更高版本：

```sh
npm ci --ignore-scripts
npm test
npm run typecheck
npm run build
```

当前 51 项回归测试覆盖 AWS 官方签名样例、独立 `aws4` 签名兼容性、原鉴权绕过、请求篡改、过期 URL、密钥信息泄露、桶路径边界、配置格式错误与流式上传转发。运行时代码仅使用 Workers 原生 Web API，签名测试库是开发依赖。

本地调试时，把四个变量写在已忽略的 `.dev.vars` 文件中，再运行 `npm run dev`。不要将真实凭据放进命令历史。

参考：[AWS S3 Signature V4](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html)、[预签名 URL](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-query-string-auth.html)、[B2 与 Cloudflare](https://www.backblaze.com/docs/cloud-storage-deliver-private-backblaze-b2-content-through-cloudflare-cdn)。

## License

沿用上游声明：MIT。
