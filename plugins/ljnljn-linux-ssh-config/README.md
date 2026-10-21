# ljnljn-linux-ssh-config

LovelyCarve **LPP v2** 原生插件，结构化读取 Linux 系统上的 OpenSSH 配置。

- 插件 ID：`org.ljnljn.linux-ssh-config`
- 版本：`0.1.0`
- 作用域：`system`，平台 `linux`
- 记录类型：`linux.ssh.server_setting`、`linux.ssh.client_setting`、`linux.ssh.authorized_key`、`linux.ssh.host_key`

## 分析器

| 分析器 | 读取内容 |
| --- | --- |
| `sshd_config` | `/etc/ssh/sshd_config` 与 `sshd_config.d/*.conf`，保留 `Match` 作用域、行号和来源 |
| `ssh_config` | `/etc/ssh/ssh_config`、`ssh_config.d/*.conf`、root 与用户 `~/.ssh/config`，保留 `Host` 作用域 |
| `authorized_keys` | root 与 `home/*/.ssh/authorized_keys` 的密钥类型、位数、SHA256 指纹、注释和授权选项 |
| `host_keys` | `/etc/ssh/ssh_host_*_key.pub` 的类型、位数、SHA256 指纹和注释 |

配置项按 `关键字 / 值 / 来源文件 / 行号 / 作用域` 输出，不做“猜测生效值”。`Include`
指令会作为配置项记录；标准 drop-in 目录已经声明为输入，其他 Include 路径不会被
插件自行跟随。公钥指纹使用 OpenSSH 的 `SHA256:...` 格式，不输出私钥内容。

## 构建

```bash
cargo test --locked
cargo build --release --locked
```

需要 LovelyCarve v2 宿主（protocol 2）。Windows 产物为
`target/release/ljnljn_linux_ssh_config.dll`，Linux 为 `.so`。

## 安装

把 `plugin.toml`、对应平台的动态库、`schema.json` 和 `locales/` 放入同一个插件包
目录，重启 LovelyCarve 后选择 Linux 系统运行分析器。Release 中的 `.lcpkg` 可直接
通过「设置 → 插件」安装。

插件只读检材，不执行检材内容，不访问网络。配置解析是静态读取，不运行 `sshd -T`，
因此 `Include`、多文件优先级和条件匹配的最终生效值仍需结合原始文件复核。

## 许可证

AGPL-3.0-only，见 [LICENSE](LICENSE)。
