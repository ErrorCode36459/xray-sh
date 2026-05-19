#!/usr/bin/env bash
set -euo pipefail

# =========================================================
# Xray 多协议一键部署脚本 v9
# 目录：/etc/xray/config.json
# 管理入口：xray
# 支持：
#   1) VLESS+TLS+Vision+TCP
#   2) VLESS+Reality+uTLS+Vision
#   3) VLESS+Reality+XHTTP
#   4) VLESS+TLS+XHTTP
#   5) Shadowsocks 2022
#   6) VLESS+TLS+WS
#   7) VMess+TLS+WS
# =========================================================

info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*" >&2; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }
trap 'code=$?; line=$LINENO; err "脚本在第 ${line} 行出错，退出码 ${code}"' ERR

CONFIG_DIR="/etc/xray"
CONFIG_PATH="${CONFIG_DIR}/config.json"
CACHE_FILE="${CONFIG_DIR}/.config_cache"
PROTOCOL_FILE="${CONFIG_DIR}/.protocols"
URI_FILE="${CONFIG_DIR}/uris.txt"
CERT_DIR="${CONFIG_DIR}/certs"
TLS_CERT_FILE="${CERT_DIR}/fullchain.pem"
TLS_KEY_FILE="${CERT_DIR}/privkey.pem"
XRAY_BIN="/usr/local/bin/xray"
XRAY_ASSET_DIR="/usr/local/share/xray"
SERVICE_NAME="xray"
PANEL_PATH="/usr/local/sbin/xray"

# -----------------------
# 系统检测与基础工具
# -----------------------
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="${ID:-}"
        OS_ID_LIKE="${ID_LIKE:-}"
    else
        OS_ID=""
        OS_ID_LIKE=""
    fi

    if echo "$OS_ID $OS_ID_LIKE" | grep -qi "alpine"; then
        OS="alpine"
    elif echo "$OS_ID $OS_ID_LIKE" | grep -Ei "debian|ubuntu" >/dev/null; then
        OS="debian"
    elif echo "$OS_ID $OS_ID_LIKE" | grep -Ei "centos|rhel|fedora|rocky|almalinux" >/dev/null; then
        OS="redhat"
    else
        OS="unknown"
    fi
}

show_banner() {
    echo
    echo "=============================================="
    echo "        Xray 多协议一键部署脚本"
    echo "=============================================="
    echo
}

check_root() {
    if [ "$(id -u)" != "0" ]; then
        err "此脚本需要 root 权限"
        err "请使用 root 用户执行：sudo bash install-xray-sh-v9.sh"
        exit 1
    fi
}

install_deps() {
    info "安装系统依赖..."
    case "$OS" in
        alpine)
            apk update || { err "apk update 失败"; exit 1; }
            apk add --no-cache bash curl ca-certificates openssl openrc jq unzip tar coreutils grep sed gawk socat || {
                err "依赖安装失败"; exit 1;
            }
            ;;
        debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y || { err "apt update 失败"; exit 1; }
            apt-get install -y curl ca-certificates openssl jq unzip tar coreutils gawk socat || {
                err "依赖安装失败"; exit 1;
            }
            ;;
        redhat)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y curl ca-certificates openssl jq unzip tar coreutils gawk socat || {
                    err "依赖安装失败"; exit 1;
                }
            else
                yum install -y curl ca-certificates openssl jq unzip tar coreutils gawk socat || {
                    err "依赖安装失败"; exit 1;
                }
            fi
            ;;
        *)
            warn "未识别的系统类型，尝试继续..."
            ;;
    esac
    info "依赖安装完成"
}

rand_port() {
    shuf -i 10000-60000 -n 1 2>/dev/null || echo $((RANDOM % 50001 + 10000))
}

rand_pass() {
    local bytes="${1:-32}"
    openssl rand -base64 "$bytes" 2>/dev/null | tr -d '\n\r' || head -c "$bytes" /dev/urandom | base64 | tr -d '\n\r'
}

rand_uuid() {
    local bin=""
    if [ -x "$XRAY_BIN" ]; then
        bin="$XRAY_BIN"
    elif [ -x /usr/bin/xray ] && [ ! /usr/bin/xray -ef "$PANEL_PATH" ] 2>/dev/null; then
        bin="/usr/bin/xray"
    fi

    if [ -n "$bin" ]; then
        "$bin" uuid 2>/dev/null | head -n1
    elif [ -f /proc/sys/kernel/random/uuid ]; then
        cat /proc/sys/kernel/random/uuid
    else
        openssl rand -hex 16 | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1\2\3\4-\5\6-\7\8-\9\10-\11\12\13\14\15\16/'
    fi
}

rand_short_id() {
    openssl rand -hex 8 2>/dev/null || echo "0123456789abcdef"
}

rand_path() {
    echo "/$(openssl rand -hex 4 2>/dev/null || echo xray)"
}

url_encode() {
    local s="$1"
    s="${s//%/%25}"; s="${s// /%20}"; s="${s//:/%3A}"; s="${s//+/%2B}"; s="${s//\//%2F}"
    s="${s//=/%3D}"; s="${s//#/%23}"; s="${s//&/%26}"; s="${s//\?/%3F}"
    echo "$s"
}

valid_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

read_port_or_random() {
    local prompt="$1" input port
    while true; do
        read -r -p "$prompt" input
        port="${input:-$(rand_port)}"
        if valid_port "$port"; then
            echo "$port"
            return 0
        fi
        warn "端口必须是 1-65535 的数字，请重新输入"
    done
}

allow_port() {
    local port="$1" proto="${2:-tcp}"
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "Status: active"; then
        ufw allow "${port}/${proto}" >/dev/null 2>&1 || true
    fi
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active firewalld >/dev/null 2>&1; then
        firewall-cmd --zone=public --add-port="${port}/${proto}" --permanent >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi
}

get_public_ip() {
    local ip=""
    for url in \
        "https://api.ipify.org" \
        "https://ipinfo.io/ip" \
        "https://ifconfig.me" \
        "https://icanhazip.com" \
        "https://ipecho.net/plain"; do
        ip=$(curl -s --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]' || true)
        if [ -n "$ip" ]; then
            echo "$ip"
            return 0
        fi
    done
    echo "YOUR_SERVER_IP"
}

xray_cmd() {
    if [ -x "$XRAY_BIN" ]; then
        echo "$XRAY_BIN"
    elif [ -x /usr/bin/xray ] && [ ! /usr/bin/xray -ef "$PANEL_PATH" ] 2>/dev/null; then
        echo /usr/bin/xray
    else
        local found=""
        found=$(command -v xray 2>/dev/null || true)
        if [ -n "$found" ] && [ "$found" != "$PANEL_PATH" ]; then
            echo "$found"
        else
            return 1
        fi
    fi
}

check_xray_config() {
    local bin
    bin=$(xray_cmd) || return 1
    XRAY_LOCATION_ASSET="$XRAY_ASSET_DIR" "$bin" run -test -config "$CONFIG_PATH" >/dev/null 2>&1 \
        || XRAY_LOCATION_ASSET="$XRAY_ASSET_DIR" "$bin" test -config "$CONFIG_PATH" >/dev/null 2>&1
}

show_xray_config_error() {
    local bin
    bin=$(xray_cmd) || { err "未找到 xray 可执行文件"; return 1; }
    XRAY_LOCATION_ASSET="$XRAY_ASSET_DIR" "$bin" run -test -config "$CONFIG_PATH" \
        || XRAY_LOCATION_ASSET="$XRAY_ASSET_DIR" "$bin" test -config "$CONFIG_PATH" \
        || true
}

get_arch_suffix() {
    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) echo "64" ;;
        i386|i686) echo "32" ;;
        aarch64|arm64) echo "arm64-v8a" ;;
        armv7l|armv7*) echo "arm32-v7a" ;;
        armv6l|armv6*) echo "arm32-v6" ;;
        s390x) echo "s390x" ;;
        *) err "暂不支持的 CPU 架构: $arch"; exit 1 ;;
    esac
}

install_xray() {
    info "开始安装 Xray-core..."

    local current_bin=""
    if current_bin=$(xray_cmd 2>/dev/null); then
        local current_version
        current_version=$($current_bin version 2>/dev/null | head -n1 || echo "unknown")
        warn "检测到已安装 Xray-core: $current_version"
        read -r -p "是否重新安装/更新 Xray-core?(y/N): " REINSTALL
        if [[ ! "$REINSTALL" =~ ^[Yy]$ ]]; then
            info "跳过 Xray-core 安装"
            XRAY_BIN="$current_bin"
            mkdir -p "$XRAY_ASSET_DIR"
            return 0
        fi
    fi

    local arch version zip_url tmp_dir zip_file
    arch=$(get_arch_suffix)
    version=$(curl -fsSL --connect-timeout 10 https://api.github.com/repos/XTLS/Xray-core/releases/latest 2>/dev/null | jq -r '.tag_name // empty' || true)
    if [ -z "$version" ] || [ "$version" = "null" ]; then
        warn "获取最新版本失败，使用 latest 下载地址"
        version="latest"
    fi

    tmp_dir="/tmp/xray-install-$$"
    mkdir -p "$tmp_dir" "$XRAY_ASSET_DIR"
    zip_file="$tmp_dir/xray.zip"

    if [ "$version" = "latest" ]; then
        zip_url="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${arch}.zip"
    else
        zip_url="https://github.com/XTLS/Xray-core/releases/download/${version}/Xray-linux-${arch}.zip"
    fi

    info "下载 Xray-core: $zip_url"
    curl -fL --connect-timeout 20 --retry 3 -o "$zip_file" "$zip_url" || {
        err "Xray-core 下载失败"; rm -rf "$tmp_dir"; exit 1;
    }

    unzip -o "$zip_file" -d "$tmp_dir" >/dev/null || {
        err "Xray-core 解压失败"; rm -rf "$tmp_dir"; exit 1;
    }

    install -m 755 "$tmp_dir/xray" /usr/local/bin/xray
    [ -f "$tmp_dir/geoip.dat" ] && install -m 644 "$tmp_dir/geoip.dat" "$XRAY_ASSET_DIR/geoip.dat"
    [ -f "$tmp_dir/geosite.dat" ] && install -m 644 "$tmp_dir/geosite.dat" "$XRAY_ASSET_DIR/geosite.dat"
    ln -sf /usr/local/bin/xray /usr/bin/xray 2>/dev/null || true
    rm -rf "$tmp_dir"

    XRAY_BIN="$(xray_cmd)"
    info "Xray-core 安装成功: $($XRAY_BIN version 2>/dev/null | head -n1 || echo installed)"
}

# -----------------------
# 交互选择
# -----------------------
select_protocols() {
    info "=== 选择要部署的协议 ==="
    echo "1) VLESS+TLS+Vision+TCP"
    echo "2) VLESS+Reality+uTLS+Vision"
    echo "3) VLESS+Reality+XHTTP"
    echo "4) VLESS+TLS+XHTTP"
    echo "5) Shadowsocks 2022"
    echo "6) VLESS+TLS+WS"
    echo "7) VMess+TLS+WS"
    echo ""
    echo "请输入要部署的协议编号(多个用空格分隔，如: 1 2 4 6):"
    read -r protocol_input

    ENABLE_VLESS_TLS_VISION=false
    ENABLE_VLESS_REALITY_VISION=false
    ENABLE_VLESS_REALITY_XHTTP=false
    ENABLE_VLESS_TLS_XHTTP=false
    ENABLE_SS2022=false
    ENABLE_VLESS_TLS_WS=false
    ENABLE_VMESS_TLS_WS=false

    for num in $protocol_input; do
        case "$num" in
            1) ENABLE_VLESS_TLS_VISION=true ;;
            2) ENABLE_VLESS_REALITY_VISION=true ;;
            3) ENABLE_VLESS_REALITY_XHTTP=true ;;
            4) ENABLE_VLESS_TLS_XHTTP=true ;;
            5) ENABLE_SS2022=true ;;
            6) ENABLE_VLESS_TLS_WS=true ;;
            7) ENABLE_VMESS_TLS_WS=true ;;
            *) warn "无效选项: $num" ;;
        esac
    done

    if ! $ENABLE_VLESS_TLS_VISION && ! $ENABLE_VLESS_REALITY_VISION && ! $ENABLE_VLESS_REALITY_XHTTP && ! $ENABLE_VLESS_TLS_XHTTP && ! $ENABLE_SS2022 && ! $ENABLE_VLESS_TLS_WS && ! $ENABLE_VMESS_TLS_WS; then
        err "未选择任何协议，退出安装"
        exit 1
    fi

    mkdir -p "$CONFIG_DIR"
    cat > "$PROTOCOL_FILE" <<EOF
ENABLE_VLESS_TLS_VISION=$ENABLE_VLESS_TLS_VISION
ENABLE_VLESS_REALITY_VISION=$ENABLE_VLESS_REALITY_VISION
ENABLE_VLESS_REALITY_XHTTP=$ENABLE_VLESS_REALITY_XHTTP
ENABLE_VLESS_TLS_XHTTP=$ENABLE_VLESS_TLS_XHTTP
ENABLE_SS2022=$ENABLE_SS2022
ENABLE_VLESS_TLS_WS=$ENABLE_VLESS_TLS_WS
ENABLE_VMESS_TLS_WS=$ENABLE_VMESS_TLS_WS
EOF

    info "已选择协议:"
    if [[ "$ENABLE_VLESS_TLS_VISION" == "true" ]]; then echo "  - VLESS+TLS+Vision+TCP"; fi
    if [[ "$ENABLE_VLESS_REALITY_VISION" == "true" ]]; then echo "  - VLESS+Reality+uTLS+Vision"; fi
    if [[ "$ENABLE_VLESS_REALITY_XHTTP" == "true" ]]; then echo "  - VLESS+Reality+XHTTP"; fi
    if [[ "$ENABLE_VLESS_TLS_XHTTP" == "true" ]]; then echo "  - VLESS+TLS+XHTTP"; fi
    if [[ "$ENABLE_SS2022" == "true" ]]; then echo "  - Shadowsocks 2022"; fi
    if [[ "$ENABLE_VLESS_TLS_WS" == "true" ]]; then echo "  - VLESS+TLS+WS"; fi
    if [[ "$ENABLE_VMESS_TLS_WS" == "true" ]]; then echo "  - VMess+TLS+WS"; fi

    return 0
}

need_tls() {
    [[ "${ENABLE_VLESS_TLS_VISION:-false}" == "true" || "${ENABLE_VLESS_TLS_XHTTP:-false}" == "true" || "${ENABLE_VLESS_TLS_WS:-false}" == "true" || "${ENABLE_VMESS_TLS_WS:-false}" == "true" ]]
}

need_reality() {
    [[ "${ENABLE_VLESS_REALITY_VISION:-false}" == "true" || "${ENABLE_VLESS_REALITY_XHTTP:-false}" == "true" ]]
}

read_common_options() {
    echo ""
    echo "请输入节点名称(留空则默认协议名):"
    read -r user_name
    if [[ -n "$user_name" ]]; then
        suffix="-${user_name}"
        echo "$suffix" > /root/node_names.txt
    else
        suffix=""
        rm -f /root/node_names.txt 2>/dev/null || true
    fi

    echo ""
    read -r -p "请输入节点连接 IP 或 DDNS 域名(留空默认出口IP): " CUSTOM_IP
    CUSTOM_IP="$(echo "$CUSTOM_IP" | tr -d '[:space:]')"

    if need_tls; then
        echo ""
        read -r -p "请输入 TLS 域名/SNI(留空默认 www.bing.com): " TLS_DOMAIN
        TLS_DOMAIN="$(echo "${TLS_DOMAIN:-www.bing.com}" | tr -d '[:space:]')"
    else
        TLS_DOMAIN="www.bing.com"
    fi

    if need_reality; then
        echo ""
        read -r -p "请输入 Reality 的 SNI/目标站(留空默认 www.microsoft.com): " REALITY_SNI
        REALITY_SNI="$(echo "${REALITY_SNI:-www.microsoft.com}" | tr -d '[:space:]')"
    else
        REALITY_SNI="www.microsoft.com"
    fi
}

generate_tls_cert() {
    if ! need_tls; then
        return 0
    fi

    mkdir -p "$CERT_DIR"
    echo ""
    info "=== 配置 TLS 证书 ==="
    echo "1) 自动生成自签证书（默认，配置能直接启动；客户端一般需要允许不安全证书）"
    echo "2) 使用已有证书文件"
    echo "3) 尝试使用 acme.sh 申请 Let's Encrypt 证书（需要域名已解析到本机，80 端口可用）"
    read -r -p "请输入选择(默认 1): " cert_choice
    cert_choice="${cert_choice:-1}"

    case "$cert_choice" in
        2)
            read -r -p "请输入 fullchain.pem 路径: " input_cert
            read -r -p "请输入 privkey.pem 路径: " input_key
            if [ ! -f "$input_cert" ] || [ ! -f "$input_key" ]; then
                err "证书或私钥文件不存在"
                exit 1
            fi
            cp "$input_cert" "$TLS_CERT_FILE"
            cp "$input_key" "$TLS_KEY_FILE"
            ;;
        3)
            if [ -z "$TLS_DOMAIN" ] || [ "$TLS_DOMAIN" = "www.bing.com" ]; then
                warn "使用默认证书域名不适合申请证书，将改用自签证书"
            else
                info "尝试安装/调用 acme.sh 申请证书..."
                curl https://get.acme.sh | sh -s email=admin@"$TLS_DOMAIN" >/tmp/acme-install.log 2>&1 || warn "acme.sh 安装可能失败，准备降级自签证书"
                if [ -x "$HOME/.acme.sh/acme.sh" ]; then
                    "$HOME/.acme.sh/acme.sh" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
                    "$HOME/.acme.sh/acme.sh" --issue -d "$TLS_DOMAIN" --standalone --force --keylength ec-256 || warn "证书申请失败，准备降级自签证书"
                    "$HOME/.acme.sh/acme.sh" --install-cert -d "$TLS_DOMAIN" --ecc \
                        --fullchain-file "$TLS_CERT_FILE" \
                        --key-file "$TLS_KEY_FILE" \
                        --reloadcmd "systemctl restart xray 2>/dev/null || true" || warn "证书安装失败，准备降级自签证书"
                fi
            fi
            if [ ! -f "$TLS_CERT_FILE" ] || [ ! -f "$TLS_KEY_FILE" ]; then
                warn "未获取到有效 ACME 证书，自动生成自签证书"
                openssl req -x509 -newkey rsa:2048 -nodes \
                    -keyout "$TLS_KEY_FILE" \
                    -out "$TLS_CERT_FILE" \
                    -days 3650 \
                    -subj "/CN=${TLS_DOMAIN}" >/dev/null 2>&1 || { err "自签证书生成失败"; exit 1; }
            fi
            ;;
        *)
            openssl req -x509 -newkey rsa:2048 -nodes \
                -keyout "$TLS_KEY_FILE" \
                -out "$TLS_CERT_FILE" \
                -days 3650 \
                -subj "/CN=${TLS_DOMAIN}" >/dev/null 2>&1 || { err "自签证书生成失败"; exit 1; }
            ;;
    esac

    chmod 600 "$TLS_KEY_FILE" 2>/dev/null || true
    info "TLS 证书已准备: $TLS_CERT_FILE"
}

generate_reality_keys() {
    if ! need_reality; then
        return 0
    fi

    info "生成 Reality x25519 密钥对..."
    local bin key_output
    bin=$(xray_cmd) || { err "未找到 xray，无法生成 Reality 密钥"; exit 1; }
    key_output=$($bin x25519 2>&1) || {
        err "生成 Reality 密钥失败"
        echo "$key_output"
        exit 1
    }

    # 新版 Xray 可能输出 Private key / Public key，也可能输出 PrivateKey / Password
    REALITY_PRIVATE_KEY=$(echo "$key_output" | grep -Ei 'Private[[:space:]]*key|PrivateKey' | awk -F ':' '{print $NF}' | awk '{print $NF}' | tr -d '\r')
    REALITY_PUBLIC_KEY=$(echo "$key_output" | grep -Ei 'Public[[:space:]]*key|PublicKey|Password' | awk -F ':' '{print $NF}' | awk '{print $NF}' | tail -n1 | tr -d '\r')

    if [ -z "${REALITY_PRIVATE_KEY:-}" ] || [ -z "${REALITY_PUBLIC_KEY:-}" ]; then
        err "Reality 密钥解析失败"
        echo "$key_output"
        exit 1
    fi

    [ "$ENABLE_VLESS_REALITY_VISION" = "true" ] && REALITY_VISION_SID=$(rand_short_id) || REALITY_VISION_SID=""
    [ "$ENABLE_VLESS_REALITY_XHTTP" = "true" ] && REALITY_XHTTP_SID=$(rand_short_id) || REALITY_XHTTP_SID=""

    echo -n "$REALITY_PUBLIC_KEY" > "${CONFIG_DIR}/.reality_pub"
    info "Reality 密钥已生成"
}

get_config() {
    info "开始配置端口、UUID 和密码..."

    if $ENABLE_VLESS_TLS_VISION; then
        PORT_VLESS_TLS_VISION=$(read_port_or_random "请输入 VLESS+TLS+Vision+TCP 端口(留空随机): ")
        UUID_VLESS_TLS_VISION=$(rand_uuid)
        allow_port "$PORT_VLESS_TLS_VISION" tcp
    fi

    if $ENABLE_VLESS_REALITY_VISION; then
        PORT_VLESS_REALITY_VISION=$(read_port_or_random "请输入 VLESS+Reality+uTLS+Vision 端口(留空随机): ")
        UUID_VLESS_REALITY_VISION=$(rand_uuid)
        allow_port "$PORT_VLESS_REALITY_VISION" tcp
    fi

    if $ENABLE_VLESS_REALITY_XHTTP; then
        PORT_VLESS_REALITY_XHTTP=$(read_port_or_random "请输入 VLESS+Reality+XHTTP 端口(留空随机): ")
        UUID_VLESS_REALITY_XHTTP=$(rand_uuid)
        read -r -p "请输入 Reality XHTTP 路径(留空随机): " XHTTP_PATH
        XHTTP_PATH="${XHTTP_PATH:-$(rand_path)}"
        [[ "$XHTTP_PATH" != /* ]] && XHTTP_PATH="/${XHTTP_PATH}"
        allow_port "$PORT_VLESS_REALITY_XHTTP" tcp
    fi

    if $ENABLE_VLESS_TLS_XHTTP; then
        PORT_VLESS_TLS_XHTTP=$(read_port_or_random "请输入 VLESS+TLS+XHTTP 端口(留空随机): ")
        UUID_VLESS_TLS_XHTTP=$(rand_uuid)
        read -r -p "请输入 TLS XHTTP 路径(留空随机): " TLS_XHTTP_PATH
        TLS_XHTTP_PATH="${TLS_XHTTP_PATH:-$(rand_path)}"
        [[ "$TLS_XHTTP_PATH" != /* ]] && TLS_XHTTP_PATH="/${TLS_XHTTP_PATH}"
        allow_port "$PORT_VLESS_TLS_XHTTP" tcp
    fi

    if $ENABLE_SS2022; then
        PORT_SS2022=$(read_port_or_random "请输入 Shadowsocks 2022 端口(留空随机): ")
        SS2022_METHOD="2022-blake3-aes-128-gcm"
        SS2022_PASSWORD=$(rand_pass 16)
        allow_port "$PORT_SS2022" tcp
        allow_port "$PORT_SS2022" udp
    fi

    if $ENABLE_VLESS_TLS_WS; then
        PORT_VLESS_TLS_WS=$(read_port_or_random "请输入 VLESS+TLS+WS 端口(留空随机): ")
        UUID_VLESS_TLS_WS=$(rand_uuid)
        read -r -p "请输入 VLESS WS 路径(留空随机): " VLESS_WS_PATH
        VLESS_WS_PATH="${VLESS_WS_PATH:-$(rand_path)}"
        [[ "$VLESS_WS_PATH" != /* ]] && VLESS_WS_PATH="/${VLESS_WS_PATH}"
        allow_port "$PORT_VLESS_TLS_WS" tcp
    fi

    if $ENABLE_VMESS_TLS_WS; then
        PORT_VMESS_TLS_WS=$(read_port_or_random "请输入 VMess+TLS+WS 端口(留空随机): ")
        UUID_VMESS_TLS_WS=$(rand_uuid)
        read -r -p "请输入 VMess WS 路径(留空随机): " VMESS_WS_PATH
        VMESS_WS_PATH="${VMESS_WS_PATH:-$(rand_path)}"
        [[ "$VMESS_WS_PATH" != /* ]] && VMESS_WS_PATH="/${VMESS_WS_PATH}"
        allow_port "$PORT_VMESS_TLS_WS" tcp
    fi

    info "端口、UUID 和密码配置完成"
}

# -----------------------
# Xray 配置生成
# -----------------------
append_inbound_vless_tls_vision() {
    inbounds=$(jq -n \
      --argjson arr "$inbounds" \
      --argjson port "$PORT_VLESS_TLS_VISION" \
      --arg uuid "$UUID_VLESS_TLS_VISION" \
      --arg cert "$TLS_CERT_FILE" \
      --arg key "$TLS_KEY_FILE" '
      $arr + [{
        "tag": "vless-tls-vision-in",
        "listen": "::",
        "port": $port,
        "protocol": "vless",
        "settings": {
          "clients": [{"id": $uuid, "flow": "xtls-rprx-vision", "email": "vless-tls-vision"}],
          "decryption": "none"
        },
        "streamSettings": {
          "network": "tcp",
          "security": "tls",
          "tlsSettings": {"certificates": [{"certificateFile": $cert, "keyFile": $key}]}
        },
        "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}
      }]')
}

append_inbound_vless_reality_vision() {
    inbounds=$(jq -n \
      --argjson arr "$inbounds" \
      --argjson port "$PORT_VLESS_REALITY_VISION" \
      --arg uuid "$UUID_VLESS_REALITY_VISION" \
      --arg sni "$REALITY_SNI" \
      --arg private_key "$REALITY_PRIVATE_KEY" \
      --arg sid "$REALITY_VISION_SID" '
      $arr + [{
        "tag": "vless-reality-vision-in",
        "listen": "::",
        "port": $port,
        "protocol": "vless",
        "settings": {
          "clients": [{"id": $uuid, "flow": "xtls-rprx-vision", "email": "vless-reality-vision"}],
          "decryption": "none"
        },
        "streamSettings": {
          "network": "tcp",
          "security": "reality",
          "realitySettings": {
            "show": false,
            "dest": ($sni + ":443"),
            "target": ($sni + ":443"),
            "xver": 0,
            "serverNames": [$sni],
            "privateKey": $private_key,
            "shortIds": [$sid]
          }
        },
        "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}
      }]')
}

append_inbound_vless_reality_xhttp() {
    inbounds=$(jq -n \
      --argjson arr "$inbounds" \
      --argjson port "$PORT_VLESS_REALITY_XHTTP" \
      --arg uuid "$UUID_VLESS_REALITY_XHTTP" \
      --arg sni "$REALITY_SNI" \
      --arg private_key "$REALITY_PRIVATE_KEY" \
      --arg sid "$REALITY_XHTTP_SID" \
      --arg path "$XHTTP_PATH" '
      $arr + [{
        "tag": "vless-reality-xhttp-in",
        "listen": "::",
        "port": $port,
        "protocol": "vless",
        "settings": {
          "clients": [{"id": $uuid, "email": "vless-reality-xhttp"}],
          "decryption": "none"
        },
        "streamSettings": {
          "network": "xhttp",
          "xhttpSettings": {"path": $path},
          "security": "reality",
          "realitySettings": {
            "show": false,
            "dest": ($sni + ":443"),
            "target": ($sni + ":443"),
            "xver": 0,
            "serverNames": [$sni],
            "privateKey": $private_key,
            "shortIds": [$sid]
          }
        },
        "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}
      }]')
}

append_inbound_vless_tls_xhttp() {
    inbounds=$(jq -n       --argjson arr "$inbounds"       --argjson port "$PORT_VLESS_TLS_XHTTP"       --arg uuid "$UUID_VLESS_TLS_XHTTP"       --arg cert "$TLS_CERT_FILE"       --arg key "$TLS_KEY_FILE"       --arg path "$TLS_XHTTP_PATH" '
      $arr + [{
        "tag": "vless-tls-xhttp-in",
        "listen": "::",
        "port": $port,
        "protocol": "vless",
        "settings": {
          "clients": [{"id": $uuid, "email": "vless-tls-xhttp"}],
          "decryption": "none"
        },
        "streamSettings": {
          "network": "xhttp",
          "security": "tls",
          "tlsSettings": {"certificates": [{"certificateFile": $cert, "keyFile": $key}]},
          "xhttpSettings": {"path": $path}
        },
        "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}
      }]')
}

append_inbound_ss2022() {
    inbounds=$(jq -n \
      --argjson arr "$inbounds" \
      --argjson port "$PORT_SS2022" \
      --arg method "$SS2022_METHOD" \
      --arg password "$SS2022_PASSWORD" '
      $arr + [{
        "tag": "ss2022-in",
        "listen": "::",
        "port": $port,
        "protocol": "shadowsocks",
        "settings": {
          "method": $method,
          "password": $password,
          "network": "tcp,udp"
        },
        "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}
      }]')
}

append_inbound_vless_tls_ws() {
    inbounds=$(jq -n \
      --argjson arr "$inbounds" \
      --argjson port "$PORT_VLESS_TLS_WS" \
      --arg uuid "$UUID_VLESS_TLS_WS" \
      --arg cert "$TLS_CERT_FILE" \
      --arg key "$TLS_KEY_FILE" \
      --arg path "$VLESS_WS_PATH" '
      $arr + [{
        "tag": "vless-tls-ws-in",
        "listen": "::",
        "port": $port,
        "protocol": "vless",
        "settings": {
          "clients": [{"id": $uuid, "email": "vless-tls-ws"}],
          "decryption": "none"
        },
        "streamSettings": {
          "network": "websocket",
          "security": "tls",
          "tlsSettings": {"certificates": [{"certificateFile": $cert, "keyFile": $key}]},
          "wsSettings": {"path": $path}
        },
        "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}
      }]')
}

append_inbound_vmess_tls_ws() {
    inbounds=$(jq -n \
      --argjson arr "$inbounds" \
      --argjson port "$PORT_VMESS_TLS_WS" \
      --arg uuid "$UUID_VMESS_TLS_WS" \
      --arg cert "$TLS_CERT_FILE" \
      --arg key "$TLS_KEY_FILE" \
      --arg path "$VMESS_WS_PATH" '
      $arr + [{
        "tag": "vmess-tls-ws-in",
        "listen": "::",
        "port": $port,
        "protocol": "vmess",
        "settings": {
          "clients": [{"id": $uuid, "alterId": 0, "email": "vmess-tls-ws"}]
        },
        "streamSettings": {
          "network": "websocket",
          "security": "tls",
          "tlsSettings": {"certificates": [{"certificateFile": $cert, "keyFile": $key}]},
          "wsSettings": {"path": $path}
        },
        "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}
      }]')
}

create_config() {
    info "生成 Xray 配置文件: $CONFIG_PATH"
    mkdir -p "$CONFIG_DIR"
    inbounds="[]"

    $ENABLE_VLESS_TLS_VISION && append_inbound_vless_tls_vision
    $ENABLE_VLESS_REALITY_VISION && append_inbound_vless_reality_vision
    $ENABLE_VLESS_REALITY_XHTTP && append_inbound_vless_reality_xhttp
    $ENABLE_VLESS_TLS_XHTTP && append_inbound_vless_tls_xhttp
    $ENABLE_SS2022 && append_inbound_ss2022
    $ENABLE_VLESS_TLS_WS && append_inbound_vless_tls_ws
    $ENABLE_VMESS_TLS_WS && append_inbound_vmess_tls_ws

    jq -n \
      --argjson inbounds "$inbounds" '
      {
        "log": {"loglevel": "warning"},
        "inbounds": $inbounds,
        "outbounds": [
          {"tag": "direct-out", "protocol": "freedom"},
          {"tag": "block-out", "protocol": "blackhole"}
        ],
        "routing": {"domainStrategy": "AsIs", "rules": []}
      }' > "$CONFIG_PATH"

    if check_xray_config; then
        info "Xray 配置文件验证通过"
    else
        err "Xray 配置文件验证失败，请检查 $CONFIG_PATH"
        show_xray_config_error
        exit 1
    fi

    cat > "$CACHE_FILE" <<EOF
ENABLE_VLESS_TLS_VISION=$ENABLE_VLESS_TLS_VISION
ENABLE_VLESS_REALITY_VISION=$ENABLE_VLESS_REALITY_VISION
ENABLE_VLESS_REALITY_XHTTP=$ENABLE_VLESS_REALITY_XHTTP
ENABLE_VLESS_TLS_XHTTP=$ENABLE_VLESS_TLS_XHTTP
ENABLE_SS2022=$ENABLE_SS2022
ENABLE_VLESS_TLS_WS=$ENABLE_VLESS_TLS_WS
ENABLE_VMESS_TLS_WS=$ENABLE_VMESS_TLS_WS
CUSTOM_IP=$CUSTOM_IP
TLS_DOMAIN=$TLS_DOMAIN
REALITY_SNI=$REALITY_SNI
TLS_CERT_FILE=$TLS_CERT_FILE
TLS_KEY_FILE=$TLS_KEY_FILE
EOF

    $ENABLE_VLESS_TLS_VISION && cat >> "$CACHE_FILE" <<EOF
PORT_VLESS_TLS_VISION=$PORT_VLESS_TLS_VISION
UUID_VLESS_TLS_VISION=$UUID_VLESS_TLS_VISION
EOF
    $ENABLE_VLESS_REALITY_VISION && cat >> "$CACHE_FILE" <<EOF
PORT_VLESS_REALITY_VISION=$PORT_VLESS_REALITY_VISION
UUID_VLESS_REALITY_VISION=$UUID_VLESS_REALITY_VISION
REALITY_PRIVATE_KEY=$REALITY_PRIVATE_KEY
REALITY_PUBLIC_KEY=$REALITY_PUBLIC_KEY
REALITY_VISION_SID=$REALITY_VISION_SID
EOF
    $ENABLE_VLESS_REALITY_XHTTP && cat >> "$CACHE_FILE" <<EOF
PORT_VLESS_REALITY_XHTTP=$PORT_VLESS_REALITY_XHTTP
UUID_VLESS_REALITY_XHTTP=$UUID_VLESS_REALITY_XHTTP
XHTTP_PATH=$XHTTP_PATH
REALITY_PRIVATE_KEY=$REALITY_PRIVATE_KEY
REALITY_PUBLIC_KEY=$REALITY_PUBLIC_KEY
REALITY_XHTTP_SID=$REALITY_XHTTP_SID
EOF
    $ENABLE_VLESS_TLS_XHTTP && cat >> "$CACHE_FILE" <<EOF
PORT_VLESS_TLS_XHTTP=$PORT_VLESS_TLS_XHTTP
UUID_VLESS_TLS_XHTTP=$UUID_VLESS_TLS_XHTTP
TLS_XHTTP_PATH=$TLS_XHTTP_PATH
EOF
    $ENABLE_SS2022 && cat >> "$CACHE_FILE" <<EOF
PORT_SS2022=$PORT_SS2022
SS2022_METHOD=$SS2022_METHOD
SS2022_PASSWORD=$SS2022_PASSWORD
EOF
    $ENABLE_VLESS_TLS_WS && cat >> "$CACHE_FILE" <<EOF
PORT_VLESS_TLS_WS=$PORT_VLESS_TLS_WS
UUID_VLESS_TLS_WS=$UUID_VLESS_TLS_WS
VLESS_WS_PATH=$VLESS_WS_PATH
EOF
    $ENABLE_VMESS_TLS_WS && cat >> "$CACHE_FILE" <<EOF
PORT_VMESS_TLS_WS=$PORT_VMESS_TLS_WS
UUID_VMESS_TLS_WS=$UUID_VMESS_TLS_WS
VMESS_WS_PATH=$VMESS_WS_PATH
EOF

    info "配置缓存已保存到 $CACHE_FILE"
}

# -----------------------
# 服务配置
# -----------------------
setup_service() {
    info "配置系统服务..."
    local SERVICE_PATH

    if [ "$OS" = "alpine" ]; then
        SERVICE_PATH="/etc/init.d/xray"
        cat > "$SERVICE_PATH" <<OPENRC
#!/sbin/openrc-run

name="xray"
description="Xray Proxy Server"
command="$XRAY_BIN"
command_args="run -config $CONFIG_PATH"
pidfile="/run/\${RC_SVCNAME}.pid"
command_background="yes"
output_log="/var/log/xray.log"
error_log="/var/log/xray.err"
supervisor=supervise-daemon
supervise_daemon_args="--respawn-max 0 --respawn-delay 5"

export XRAY_LOCATION_ASSET="$XRAY_ASSET_DIR"

depend() {
    need net
    after firewall
}

start_pre() {
    checkpath --directory --mode 0755 /var/log
    checkpath --directory --mode 0755 /run
}
OPENRC
        chmod +x "$SERVICE_PATH"
        rc-update add xray default >/dev/null 2>&1 || warn "添加开机自启失败"
        rc-service xray restart || {
            err "服务启动失败"
            tail -50 /var/log/xray.err 2>/dev/null || tail -50 /var/log/xray.log 2>/dev/null || true
            exit 1
        }
        sleep 2
        rc-service xray status >/dev/null 2>&1 && info "✅ OpenRC 服务已启动" || { err "服务状态异常"; exit 1; }
    else
        SERVICE_PATH="/etc/systemd/system/xray.service"
        cat > "$SERVICE_PATH" <<SYSTEMD
[Unit]
Description=Xray Proxy Server
Documentation=https://github.com/XTLS/Xray-core
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$XRAY_ASSET_DIR
Environment=XRAY_LOCATION_ASSET=$XRAY_ASSET_DIR
ExecStart=$XRAY_BIN run -config $CONFIG_PATH
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SYSTEMD
        systemctl daemon-reload
        systemctl enable xray >/dev/null 2>&1
        systemctl restart xray || {
            err "服务启动失败"
            journalctl -u xray -n 80 --no-pager || true
            exit 1
        }
        sleep 2
        systemctl is-active xray >/dev/null 2>&1 && info "✅ Systemd 服务已启动" || { err "服务状态异常"; exit 1; }
    fi

    info "服务配置完成: $SERVICE_PATH"
}

# -----------------------
# URI 生成
# -----------------------
make_vmess_uri() {
    local ps="$1" host="$2" port="$3" uuid="$4" sni="$5" path="$6" insecure="$7"
    local json b64
    json=$(jq -nc \
      --arg ps "$ps" \
      --arg add "$host" \
      --arg port "$port" \
      --arg id "$uuid" \
      --arg host "$sni" \
      --arg sni "$sni" \
      --arg path "$path" \
      --arg allowInsecure "$insecure" '{
        v: "2",
        ps: $ps,
        add: $add,
        port: $port,
        id: $id,
        aid: "0",
        scy: "auto",
        net: "ws",
        type: "none",
        host: $host,
        path: $path,
        tls: "tls",
        sni: $sni,
        alpn: "http/1.1",
        allowInsecure: $allowInsecure
      }')
    b64=$(printf "%s" "$json" | base64 -w0 2>/dev/null || printf "%s" "$json" | base64 | tr -d '\n')
    echo "vmess://${b64}"
}

generate_uris() {
    local host="$PUB_IP"
    local tls_insecure="1"
    local enc_path

    : > "$URI_FILE"

    if $ENABLE_VLESS_TLS_VISION; then
        echo "=== VLESS+TLS+Vision+TCP ===" >> "$URI_FILE"
        echo "vless://${UUID_VLESS_TLS_VISION}@${host}:${PORT_VLESS_TLS_VISION}?encryption=none&flow=xtls-rprx-vision&security=tls&type=tcp&sni=${TLS_DOMAIN}&fp=chrome&allowInsecure=${tls_insecure}#vless-tls-vision${suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi

    if $ENABLE_VLESS_REALITY_VISION; then
        echo "=== VLESS+Reality+uTLS+Vision ===" >> "$URI_FILE"
        echo "vless://${UUID_VLESS_REALITY_VISION}@${host}:${PORT_VLESS_REALITY_VISION}?encryption=none&flow=xtls-rprx-vision&security=reality&type=tcp&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_VISION_SID}&spx=%2F#reality-vision${suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi

    if $ENABLE_VLESS_REALITY_XHTTP; then
        enc_path=$(url_encode "$XHTTP_PATH")
        echo "=== VLESS+Reality+XHTTP ===" >> "$URI_FILE"
        echo "vless://${UUID_VLESS_REALITY_XHTTP}@${host}:${PORT_VLESS_REALITY_XHTTP}?encryption=none&security=reality&type=xhttp&path=${enc_path}&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_XHTTP_SID}#reality-xhttp${suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi

    if $ENABLE_VLESS_TLS_XHTTP; then
        enc_path=$(url_encode "$TLS_XHTTP_PATH")
        echo "=== VLESS+TLS+XHTTP ===" >> "$URI_FILE"
        echo "vless://${UUID_VLESS_TLS_XHTTP}@${host}:${PORT_VLESS_TLS_XHTTP}?encryption=none&security=tls&type=xhttp&host=${TLS_DOMAIN}&path=${enc_path}&sni=${TLS_DOMAIN}&fp=chrome&allowInsecure=${tls_insecure}#vless-tls-xhttp${suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi

    if $ENABLE_SS2022; then
        local ss_userinfo ss_b64 ss_tag
        ss_userinfo="${SS2022_METHOD}:${SS2022_PASSWORD}"
        ss_b64=$(printf "%s" "$ss_userinfo" | base64 -w0 2>/dev/null || printf "%s" "$ss_userinfo" | base64 | tr -d '\n')
        ss_tag="ss2022${suffix}"
        echo "=== Shadowsocks 2022 ===" >> "$URI_FILE"
        echo "ss://${ss_b64}@${host}:${PORT_SS2022}#${ss_tag}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi

    if $ENABLE_VLESS_TLS_WS; then
        enc_path=$(url_encode "$VLESS_WS_PATH")
        echo "=== VLESS+TLS+WS ===" >> "$URI_FILE"
        echo "vless://${UUID_VLESS_TLS_WS}@${host}:${PORT_VLESS_TLS_WS}?encryption=none&security=tls&type=ws&host=${TLS_DOMAIN}&path=${enc_path}&sni=${TLS_DOMAIN}&fp=chrome&allowInsecure=${tls_insecure}#vless-tls-ws${suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi

    if $ENABLE_VMESS_TLS_WS; then
        echo "=== VMess+TLS+WS ===" >> "$URI_FILE"
        make_vmess_uri "vmess-tls-ws${suffix}" "$host" "$PORT_VMESS_TLS_WS" "$UUID_VMESS_TLS_WS" "$TLS_DOMAIN" "$VMESS_WS_PATH" "$tls_insecure" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi
}

# -----------------------
# xray 管理面板
# -----------------------
create_xray_panel() {
    info "正在创建 xray 管理面板: $PANEL_PATH"
    mkdir -p "$(dirname "$PANEL_PATH")"
    rm -f /usr/local/bin/sb 2>/dev/null || true
    cat > "$PANEL_PATH" <<'SB_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*" >&2; }
err()  { echo -e "\033[1;31m[ERR]\033[0m $*" >&2; }
trap 'code=$?; line=$LINENO; err "脚本在第 ${line} 行出错，退出码 ${code}"' ERR

CONFIG_DIR="/etc/xray"
CONFIG_PATH="${CONFIG_DIR}/config.json"
CACHE_FILE="${CONFIG_DIR}/.config_cache"
URI_FILE="${CONFIG_DIR}/uris.txt"
SERVICE_NAME="xray"
XRAY_BIN="/usr/local/bin/xray"
XRAY_ASSET_DIR="/usr/local/share/xray"

url_encode() {
    local s="$1"
    s="${s//%/%25}"; s="${s// /%20}"; s="${s//:/%3A}"; s="${s//+/%2B}"; s="${s//\//%2F}"
    s="${s//=/%3D}"; s="${s//#/%23}"; s="${s//&/%26}"; s="${s//\?/%3F}"
    echo "$s"
}

xray_cmd() {
    if [ -x "$XRAY_BIN" ]; then
        echo "$XRAY_BIN"
    elif [ -x /usr/bin/xray ] && [ ! /usr/bin/xray -ef /usr/local/sbin/xray ] 2>/dev/null; then
        echo /usr/bin/xray
    else
        local found=""
        found=$(command -v xray 2>/dev/null || true)
        if [ -n "$found" ] && [ "$found" != "/usr/local/sbin/xray" ]; then
            echo "$found"
        else
            return 1
        fi
    fi
}

check_xray_config() {
    local bin
    bin=$(xray_cmd) || return 1
    XRAY_LOCATION_ASSET="$XRAY_ASSET_DIR" "$bin" run -test -config "$CONFIG_PATH" >/dev/null 2>&1 \
        || XRAY_LOCATION_ASSET="$XRAY_ASSET_DIR" "$bin" test -config "$CONFIG_PATH" >/dev/null 2>&1
}

show_xray_config_error() {
    local bin
    bin=$(xray_cmd) || { err "未找到 xray 可执行文件"; return 1; }
    XRAY_LOCATION_ASSET="$XRAY_ASSET_DIR" "$bin" run -test -config "$CONFIG_PATH" \
        || XRAY_LOCATION_ASSET="$XRAY_ASSET_DIR" "$bin" test -config "$CONFIG_PATH" \
        || true
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        ID="${ID:-}"; ID_LIKE="${ID_LIKE:-}"
    else
        ID=""; ID_LIKE=""
    fi
    if echo "$ID $ID_LIKE" | grep -qi "alpine"; then OS="alpine"; else OS="systemd"; fi
}

detect_os
service_start() { [ "$OS" = "alpine" ] && rc-service "$SERVICE_NAME" start || systemctl start "$SERVICE_NAME"; }
service_stop() { [ "$OS" = "alpine" ] && rc-service "$SERVICE_NAME" stop || systemctl stop "$SERVICE_NAME"; }
service_restart() { [ "$OS" = "alpine" ] && rc-service "$SERVICE_NAME" restart || systemctl restart "$SERVICE_NAME"; }
service_status() { [ "$OS" = "alpine" ] && rc-service "$SERVICE_NAME" status || systemctl status "$SERVICE_NAME" --no-pager; }

get_public_ip() {
    local ip=""
    for url in "https://api.ipify.org" "https://ipinfo.io/ip" "https://ifconfig.me" "https://icanhazip.com"; do
        ip=$(curl -s --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]' || true)
        [ -n "$ip" ] && echo "$ip" && return 0
    done
    echo "YOUR_SERVER_IP"
}

make_vmess_uri() {
    local ps="$1" host="$2" port="$3" uuid="$4" sni="$5" path="$6" insecure="$7"
    local json b64
    json=$(jq -nc \
      --arg ps "$ps" --arg add "$host" --arg port "$port" --arg id "$uuid" \
      --arg host "$sni" --arg sni "$sni" --arg path "$path" --arg allowInsecure "$insecure" '{
        v:"2", ps:$ps, add:$add, port:$port, id:$id, aid:"0", scy:"auto", net:"ws",
        type:"none", host:$host, path:$path, tls:"tls", sni:$sni, alpn:"http/1.1", allowInsecure:$allowInsecure
      }')
    b64=$(printf "%s" "$json" | base64 -w0 2>/dev/null || printf "%s" "$json" | base64 | tr -d '\n')
    echo "vmess://${b64}"
}

read_config() {
    [ -f "$CACHE_FILE" ] || { err "未找到缓存文件: $CACHE_FILE"; return 1; }
    # shellcheck disable=SC1090
    . "$CACHE_FILE"
    ENABLE_VLESS_TLS_VISION="${ENABLE_VLESS_TLS_VISION:-false}"
    ENABLE_VLESS_REALITY_VISION="${ENABLE_VLESS_REALITY_VISION:-false}"
    ENABLE_VLESS_REALITY_XHTTP="${ENABLE_VLESS_REALITY_XHTTP:-false}"
    ENABLE_VLESS_TLS_XHTTP="${ENABLE_VLESS_TLS_XHTTP:-false}"
    ENABLE_SS2022="${ENABLE_SS2022:-false}"
    ENABLE_VLESS_TLS_WS="${ENABLE_VLESS_TLS_WS:-false}"
    ENABLE_VMESS_TLS_WS="${ENABLE_VMESS_TLS_WS:-false}"
    CUSTOM_IP="${CUSTOM_IP:-}"
    TLS_DOMAIN="${TLS_DOMAIN:-www.bing.com}"
    REALITY_SNI="${REALITY_SNI:-www.microsoft.com}"
    suffix=$(cat /root/node_names.txt 2>/dev/null || echo "")
}

generate_uris() {
    read_config || return 1
    local host enc_path tls_insecure ss_userinfo ss_b64
    if [ -n "${CUSTOM_IP:-}" ]; then host="$CUSTOM_IP"; else host=$(get_public_ip); fi
    tls_insecure="1"
    : > "$URI_FILE"

    if [ "$ENABLE_VLESS_TLS_VISION" = "true" ]; then
        echo "=== VLESS+TLS+Vision+TCP ===" >> "$URI_FILE"
        echo "vless://${UUID_VLESS_TLS_VISION}@${host}:${PORT_VLESS_TLS_VISION}?encryption=none&flow=xtls-rprx-vision&security=tls&type=tcp&sni=${TLS_DOMAIN}&fp=chrome&allowInsecure=${tls_insecure}#vless-tls-vision${suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi
    if [ "$ENABLE_VLESS_REALITY_VISION" = "true" ]; then
        echo "=== VLESS+Reality+uTLS+Vision ===" >> "$URI_FILE"
        echo "vless://${UUID_VLESS_REALITY_VISION}@${host}:${PORT_VLESS_REALITY_VISION}?encryption=none&flow=xtls-rprx-vision&security=reality&type=tcp&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_VISION_SID}&spx=%2F#reality-vision${suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi
    if [ "$ENABLE_VLESS_REALITY_XHTTP" = "true" ]; then
        enc_path=$(url_encode "$XHTTP_PATH")
        echo "=== VLESS+Reality+XHTTP ===" >> "$URI_FILE"
        echo "vless://${UUID_VLESS_REALITY_XHTTP}@${host}:${PORT_VLESS_REALITY_XHTTP}?encryption=none&security=reality&type=xhttp&path=${enc_path}&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=${REALITY_XHTTP_SID}#reality-xhttp${suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi
    if [ "$ENABLE_VLESS_TLS_XHTTP" = "true" ]; then
        enc_path=$(url_encode "$TLS_XHTTP_PATH")
        echo "=== VLESS+TLS+XHTTP ===" >> "$URI_FILE"
        echo "vless://${UUID_VLESS_TLS_XHTTP}@${host}:${PORT_VLESS_TLS_XHTTP}?encryption=none&security=tls&type=xhttp&host=${TLS_DOMAIN}&path=${enc_path}&sni=${TLS_DOMAIN}&fp=chrome&allowInsecure=${tls_insecure}#vless-tls-xhttp${suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi
    if [ "$ENABLE_SS2022" = "true" ]; then
        ss_userinfo="${SS2022_METHOD}:${SS2022_PASSWORD}"
        ss_b64=$(printf "%s" "$ss_userinfo" | base64 -w0 2>/dev/null || printf "%s" "$ss_userinfo" | base64 | tr -d '\n')
        echo "=== Shadowsocks 2022 ===" >> "$URI_FILE"
        echo "ss://${ss_b64}@${host}:${PORT_SS2022}#ss2022${suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi
    if [ "$ENABLE_VLESS_TLS_WS" = "true" ]; then
        enc_path=$(url_encode "$VLESS_WS_PATH")
        echo "=== VLESS+TLS+WS ===" >> "$URI_FILE"
        echo "vless://${UUID_VLESS_TLS_WS}@${host}:${PORT_VLESS_TLS_WS}?encryption=none&security=tls&type=ws&host=${TLS_DOMAIN}&path=${enc_path}&sni=${TLS_DOMAIN}&fp=chrome&allowInsecure=${tls_insecure}#vless-tls-ws${suffix}" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi
    if [ "$ENABLE_VMESS_TLS_WS" = "true" ]; then
        echo "=== VMess+TLS+WS ===" >> "$URI_FILE"
        make_vmess_uri "vmess-tls-ws${suffix}" "$host" "$PORT_VMESS_TLS_WS" "$UUID_VMESS_TLS_WS" "$TLS_DOMAIN" "$VMESS_WS_PATH" "$tls_insecure" >> "$URI_FILE"
        echo "" >> "$URI_FILE"
    fi
}

action_view_uri() {
    generate_uris || { err "生成协议链接失败"; return 1; }
    echo ""
    cat "$URI_FILE"
}

action_edit_config() {
    ${EDITOR:-nano} "$CONFIG_PATH" 2>/dev/null || ${EDITOR:-vi} "$CONFIG_PATH"
    if check_xray_config; then
        info "配置校验通过，正在重启服务"
        service_restart || warn "重启服务失败"
        generate_uris || true
    else
        warn "配置校验失败，服务未重启"
        show_xray_config_error
    fi
}

action_update() {
    info "开始更新 Xray-core..."
    bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install || {
        warn "官方安装脚本失败，请手动检查网络或 GitHub 访问"
        return 1
    }
    service_restart || warn "重启失败"
    local bin=""
    bin=$(xray_cmd 2>/dev/null || true)
    [ -n "$bin" ] && "$bin" version 2>/dev/null | head -n1 || true
}

action_uninstall() {
    read -r -p "确认卸载 Xray 和本脚本配置？(y/N): " confirm
    [[ ! "$confirm" =~ ^[Yy]$ ]] && { info "已取消"; return 0; }
    service_stop || true
    if [ "$OS" = "alpine" ]; then
        rc-update del xray default 2>/dev/null || true
        rm -f /etc/init.d/xray
    else
        systemctl disable xray 2>/dev/null || true
        rm -f /etc/systemd/system/xray.service
        systemctl daemon-reload 2>/dev/null || true
    fi
    rm -rf /etc/xray /var/log/xray* /usr/local/sbin/xray /root/node_names.txt 2>/dev/null || true
    info "卸载完成"
}

show_menu() {
    clear
    echo "=========================="
    echo " Xray 管理面板"
    echo "=========================="
    echo "1) 查看协议链接"
    echo "2) 查看配置文件路径"
    echo "3) 编辑配置文件"
    echo "4) 重启 Xray"
    echo "5) 查看 Xray 状态"
    echo "6) 查看 Xray 日志"
    echo "7) 校验配置文件"
    echo "8) 更新 Xray-core"
    echo "9) 卸载"
    echo "0) 退出"
    echo "=========================="
}

while true; do
    show_menu
    read -r -p "请输入选项: " opt
    case "$opt" in
        1) action_view_uri; read -r -p "按回车继续..." _ ;;
        2) echo "$CONFIG_PATH"; read -r -p "按回车继续..." _ ;;
        3) action_edit_config; read -r -p "按回车继续..." _ ;;
        4) service_restart && info "已重启"; read -r -p "按回车继续..." _ ;;
        5) service_status; read -r -p "按回车继续..." _ ;;
        6) [ "$OS" = "alpine" ] && tail -n 80 /var/log/xray.log || journalctl -u xray -n 80 --no-pager; read -r -p "按回车继续..." _ ;;
        7) check_xray_config && info "配置校验通过" || show_xray_config_error; read -r -p "按回车继续..." _ ;;
        8) action_update; read -r -p "按回车继续..." _ ;;
        9) action_uninstall; exit 0 ;;
        0) exit 0 ;;
        *) warn "无效选项"; sleep 1 ;;
    esac
done
SB_SCRIPT
    chmod +x "$PANEL_PATH"
    info "xray 管理面板创建完成"
}

# -----------------------
# 主流程
# -----------------------
main() {
    show_banner
    INSTALL_MODE="server"
    info "已取消模式选择，默认进入落地机部署流程"
    detect_os
    info "检测到系统: $OS (${OS_ID:-unknown})"
    check_root
    install_deps
    select_protocols
    info "进入基础参数配置..."
    read_common_options
    info "进入 Xray-core 安装/更新..."
    install_xray
    info "进入证书和 Reality 密钥准备..."
    generate_tls_cert
    generate_reality_keys
    info "进入协议端口与账号配置..."
    get_config
    info "进入 Xray 配置生成与校验..."
    create_config
    info "进入服务安装与启动..."
    setup_service

    if [ -n "${CUSTOM_IP:-}" ]; then
        PUB_IP="$CUSTOM_IP"
        info "使用用户提供的连接 IP/DDNS: $PUB_IP"
    else
        PUB_IP=$(get_public_ip)
        info "检测到公网 IP: $PUB_IP"
    fi

    generate_uris
    create_xray_panel

    echo ""
    echo "=========================================="
    info "🎉 Xray 部署完成!"
    echo "=========================================="
    echo ""
    info "📂 文件位置:"
    echo "   配置: $CONFIG_PATH"
    echo "   缓存: $CACHE_FILE"
    need_tls && echo "   证书: $TLS_CERT_FILE / $TLS_KEY_FILE"
    echo "   管理面板: $PANEL_PATH"
    echo ""
    info "📜 客户端链接:"
    sed 's/^/   /' "$URI_FILE"
    echo ""
    info "🔧 管理命令:"
    echo "   打开面板: xray"
    echo "   如果当前 SSH 会话已缓存旧 xray 路径，可先执行: hash -r"
    if [ "$OS" = "alpine" ]; then
        echo "   启动: rc-service xray start"
        echo "   停止: rc-service xray stop"
        echo "   重启: rc-service xray restart"
        echo "   状态: rc-service xray status"
        echo "   日志: tail -f /var/log/xray.log"
    else
        echo "   启动: systemctl start xray"
        echo "   停止: systemctl stop xray"
        echo "   重启: systemctl restart xray"
        echo "   状态: systemctl status xray"
        echo "   日志: journalctl -u xray -f"
    fi
    echo ""
    warn "如果使用自签 TLS 证书，客户端通常需要开启 allowInsecure/允许不安全证书；生产环境建议使用真实域名证书。"
    echo "=========================================="
}

main "$@"
