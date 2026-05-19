# Xray 多协议一键部署脚本

一个 Xray 自动化部署工具，支持多协议自选部署的解决方案。

---
## 一键部署命令

安装全功能 Xray一键脚本：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/ErrorCode36459/xray-sh/main/install-xray-sh.sh)"
```

## 主要特性

- **多系统支持** - 支持 Alpine, Debian, Ubuntu, CentOS, RHEL, Fedora 等操作系统
- **管理工具** - 输入 xray 指令进入管理界面查看节点链接、服务端控制查看等功能
- **开机自启** - 自动配置 Systemd / OpenRC 开机自启，崩溃自动拉起服务端
- **灵活端口** - 支持自动寻找空闲端口或手动指定
- **一键安装** - 自动部署 Xray 最新服务端
- **自动生成** - 自动生成 密钥和配置文件，VLESS Reality 自选或默认SNI
- **连接 IP** - 自动获取公网 IP 或手动输入 连接IP/DDNS域名 并生成客户端链接

