# ljnljn-linux-plugins

Linux 平台 LovelyCarve 插件仓库。插件使用 LPP v2（protocol 2）和类型化记录，
统一 tag 与 GitHub topic 为 `lovelycarve-plugins`。

| 插件 | LPP | 能力 |
| --- | --- | --- |
| `ljnljn-linux-ssh-config` | v2 | 结构化读取 sshd/ssh 客户端配置、authorized_keys 与主机公钥 |

## ljnljn-linux-ssh-config

- 插件 ID：`org.ljnljn.linux-ssh-config`
- 分析器：`sshd_config`、`ssh_config`、`authorized_keys`、`host_keys`
- 记录：`linux.ssh.server_setting`、`linux.ssh.client_setting`、
  `linux.ssh.authorized_key`、`linux.ssh.host_key`
- 输入：`/etc/ssh` 下的服务端/客户端配置与 drop-in、root 和用户 SSH 配置、
  root 与 `home/*` 的 `authorized_keys`、`ssh_host_*_key.pub`
- 配置项保留来源文件、行号、`Match`/`Host` 作用域；公钥输出类型、位数、
  SHA256 指纹、注释和授权选项

## 构建

每个插件是独立 Cargo 工程，仓库根目录提供共享 SDK v2：

```bash
cd plugins/ljnljn-linux-ssh-config
cargo test --locked
cargo build --release --locked
```

Release 提供 `.lcpkg`、完整平台 zip、`INDEX.json` 和 `SHA256SUMS.txt`。插件只读检材，
不执行检材内容，不访问网络。解析是静态的，不运行 `sshd -T`；`Include` 的最终生效值
仍需结合原始文件复核。

## 许可证

AGPL-3.0-only。
