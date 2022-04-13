#!/usr/bin/env bash

#====================================================
#	System Request:Debian 10+/Ubuntu 20.04+
#====================================================

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
stty erase ^?

cd "$(
  cd "$(dirname "$0")" || exit
  pwd
)" || exit

red() {
	echo -e "\033[31m\033[01m$1\033[0m"
}

green() {
	echo -e "\033[32m\033[01m$1\033[0m"
}

yellow() {
	echo -e "\033[33m\033[01m$1\033[0m"
}

Green="\033[32m"
Red="\033[31m"
Yellow="\033[33m"
Blue="\033[36m"
Font="\033[0m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
OK="${Green}[OK]${Font}"
ERROR="${Red}[ERROR]${Font}"
xray_conf_dir="/usr/local/etc/xray"
website_dir="/www/web/"
nginx_conf_dir="/etc/nginx/conf/conf.d"

cert_group="nobody"
VERSION=$(echo "${VERSION}" | awk -F "[()]" '{print $2}')

random_num=$((RANDOM % 12 + 4))
WSPATH="/$(head -n 10 /dev/urandom | md5sum | head -c ${random_num})"

function print_ok() {
  echo -e "${OK} ${Blue} $1 ${Font}"
}

function print_error() {
  echo -e "${ERROR} ${RedBG} $1 ${Font}"
}

function is_root() {
  if [[ 0 == "$UID" ]]; then
    print_ok "当前用户是 root 用户，开始安装流程"
  else
    print_error "当前用户不是 root 用户，请切换到 root 用户后重新执行脚本"
    exit 1
  fi
}

judge() {
  if [[ 0 -eq $? ]]; then
    print_ok "$1 完成"
    sleep 1
  else
    print_error "$1 失败"
    exit 1
  fi
}

function system_check() {
  source '/etc/os-release'

  if [[ "${ID}" == "debian" && ${VERSION_ID} -ge 9 ]]; then
    print_ok "当前系统为 Debian ${VERSION_ID} ${VERSION}"
    INS="apt install -y"
    # 清除可能的遗留问题
    rm -f /etc/apt/sources.list.d/nginx.list
    $INS lsb-release gnupg2

    echo "deb http://nginx.org/packages/debian $(lsb_release -cs) nginx" >/etc/apt/sources.list.d/nginx.list
    curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add -

    apt update
  elif [[ "${ID}" == "ubuntu" && $(echo "${VERSION_ID}" | cut -d '.' -f1) -ge 18 ]]; then
    print_ok "当前系统为 Ubuntu ${VERSION_ID} ${UBUNTU_CODENAME}"
    if [[ ${VERSION_ID} -ge 20 ]]; then
     INS="apt install -y"
    # 清除可能的遗留问题
    rm -f /etc/apt/sources.list.d/nginx.list
    $INS lsb-release gnupg2

    echo "deb http://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" >/etc/apt/sources.list.d/nginx.list
    curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add -
    apt update
  else
    print_error "当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内"
    exit 1
  fi

  if [[ $(grep "nogroup" /etc/group) ]]; then
    cert_group="nogroup"
  fi

  $INS dbus

  # 关闭各类防火墙
  systemctl stop firewalld
  systemctl disable firewalld
  systemctl stop nftables
  systemctl disable nftables
  systemctl stop ufw
  systemctl disable ufw
}

function nginx_install() {
  if ! command -v nginx >/dev/null 2>&1; then
    ${INS} nginx
    judge "Nginx 安装"
  else
    print_ok "Nginx 已存在"
    # 防止部分异常
    ${INS} nginx
  fi
  # 遗留问题处理
  mkdir -p /etc/nginx/conf.d >/dev/null 2>&1
}
function dependency_install() {
  ${INS} wget lsof tar
  judge "安装 wget lsof tar”
  ${INS} cron
  judge "安装 cron"
  touch /var/spool/cron/crontabs/root && chmod 600 /var/spool/cron/crontabs/root
  systemctl start cron && systemctl enable cron
  judge "crontab 自启动配置 "

  ${INS} unzip
  judge "安装 unzip"

  ${INS} curl
  judge "安装 curl"

  ${INS} systemd
  judge "安装/升级 systemd"

  ${INS} libpcre3 libpcre3-dev zlib1g-dev

  ${INS} jq

  if ! command -v jq; then
    wget -P /usr/bin https://raw.githubusercontent.com/wulabing/Xray_onekey/nginx_forward/binary/jq && chmod +x /usr/bin/jq
    judge "安装 jq"
  fi

  # 防止部分系统xray的默认bin目录缺失
  mkdir /usr/local/bin >/dev/null 2>&1
}

function basic_optimization() {
  # 最大文件打开数
  sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
  sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
  echo '* soft nofile 65536' >>/etc/security/limits.conf
  echo '* hard nofile 65536' >>/etc/security/limits.conf
}
function domain_check() {
  read -rp "请输入你的域名信息:" domain
  local_ip=$(curl -4L api64.ipify.org)
  }

function port_exist_check() {
  if [[ 0 -eq $(lsof -i:"$1" | grep -i -c "listen") ]]; then
    print_ok "$1 端口未被占用"
    sleep 1
  else
    print_error "检测到 $1 端口被占用，以下为 $1 端口占用信息"
    lsof -i:"$1"
    print_error "5s 后将尝试自动 kill 占用进程"
    sleep 5
    lsof -i:"$1" | awk '{print $2}' | grep -v "PID" | xargs kill -9
    print_ok "kill 完成"
    sleep 1
  fi
}


function xray_tmp_config_file_check_and_use() {
  if [[ -s ${xray_conf_dir}/config_tmp.json ]]; then
    mv -f ${xray_conf_dir}/config_tmp.json ${xray_conf_dir}/config.json
  else
    print_error "xray 配置文件修改异常"
  fi
}

function modify_UUID() {
  [ -z "$UUID" ] && UUID=$(cat /proc/sys/kernel/random/uuid)
  cat ${xray_conf_dir}/config.json | jq 'setpath(["inbounds",0,"settings","clients",0,"id"];"'${UUID}'")' >${xray_conf_dir}/config_tmp.json
  xray_tmp_config_file_check_and_use
  judge "Xray UUID 修改"
}

function configure_nginx() {
  nginx_conf="/etc/nginx/conf.d/${domain}.conf"
  cd /etc/nginx/conf.d/ && rm -f ${domain}.conf
cat > /etc/nginx/conf.d/${domain}.conf <<-EOF
  server {
    listen 80;
    listen [::]:80;
    root /www/web;               # 网页根目录路径
    if ($http_upgrade = "websocket") { 
   rewrite ^/(.*) ${WSPATH}?ed=2048 break;
    }
location / {
# proxy_pass http://www.ddxsku.com/;
proxy_set_header Accept-Encoding '';
}
location ${WSPATH}  {      if ($http_upgrade != "websocket") {
        return 401;     }     proxy_redirect / /;     proxy_pass http://127.0.0.1:8080; # 假设WebSocket监听在环回地址的8080端口上     proxy_http_version 1.1;     proxy_set_header Upgrade $http_upgrade;     proxy_set_header Connection "upgrade";    }
    }
EOF
  systemctl restart nginx
}




function configure_xray_ws() {
  cd /usr/local/etc/xray && rm -f config.json 
local uuid="$(cat '/proc/sys/kernel/random/uuid')"
cat > /usr/local/etc/xray/config.json  <<-EOF
{
"inbound”:[  {
"port": 8080, 
"listen":"127.0.0.1", 
"protocol": "vmess", 
"settings": {
 "clients": [
        {
          "id": “$uuid”,
          "level": 1,
          "alterId": 0
        }
      ],
      "disableInsecureEncryption": true
},
"streamSettings": {
"network": "ws", 
"wsSettings": {
"path": “$WSPATH”
}
}
} ],
"outbound": {
"protocol": "freedom",
"settings": {}
}
}
EOF
}

function xray_install() {
  curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- install
judge “安装Xray“
}


function configure_web() {
  rm -rf /www/web
  mkdir -p /www/web
  wget -O web.tar.gz https://raw.githubusercontent.com/wulabing/Xray_onekey/main/basic/web.tar.gz
  tar xzf web.tar.gz -C /www/web
  judge "站点伪装"
  rm -f web.tar.gz
}

function xray_uninstall() {
  curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh | bash -s -- remove --purge
  rm -rf $website_dir
  print_ok "是否卸载nginx [Y/N]?"
  read -r uninstall_nginx
  case $uninstall_nginx in
  [yY][eE][sS] | [yY])
    if [[ "${ID}" == "centos" || "${ID}" == "ol" ]]; then
      yum remove nginx -y
    else
      apt purge nginx -y
    fi
    ;;
  *) ;;
  esac
  print_ok "卸载完成"
  exit 0
}

function restart_all() {
  systemctl restart nginx
  judge "Nginx 启动"
  systemctl restart xray
  judge "Xray 启动"
}

function ws_information() {
  UUID=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].id | tr -d '"')
  FLOW=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].settings.clients[0].flow | tr -d '"')
  WS_PATH=$(cat ${xray_conf_dir}/config.json | jq .inbounds[0].streamSettings.wsSettings.path | tr -d '"')
  WS_PATH_WITHOUT_SLASH=$(echo $WS_PATH | tr -d '/')

  echo -e "${Red} Xray 配置信息 ${Font}"
  echo -e "${Red} 地址（address）:${Font}  $local_ip"
  echo -e "${Red} 端口（port）：${Font}  80”
  echo -e "${Red} 用户 ID（UUID）：${Font} $UUID"
  echo -e "${Red} 加密方式（security）：${Font} 自选 "
  echo -e "${Red} 传输协议（network）：${Font} ws"
  echo -e "${Red} 路径（path）：${Font} $WS_PATH "
  print_ok "————————————————————————"
  print_ok "URL 链接（VMESS + WebSocket）"
  print_ok “vmess://$UUID@$local_ip:$PORT?type=ws&security=none&path=%2f${WS_PATH_WITHOUT_SLASH}%2f”
}



function basic_ws_information() {
  print_ok "VMESS + Nginx + WebSocket 安装成功"
  ws_information
}


function install_xray_ws() {
  is_root
  system_check
  dependency_install
  basic_optimization
  domain_check
  port_exist_check 80
  xray_install
  configure_xray_ws
  nginx_install
  configure_web
  configure_nginx
  restart_all
  basic_ws_information
}

menu() {
  echo -e "—————————————— 安装向导 ——————————————"""
  echo -e "${Green}1.${Font} 安装 Xray (VMESS + Nginx + WebSocket)"
  echo -e "${Green}2.${Font} 变更 UUID"
  echo -e "${Green}3.${Font} 卸载 Xray"
  echo -e "${Green}4.${Font} 更新 Xray-core"
  echo -e "${Green}0.${Font} 退出"
  read -rp "请输入数字：" menu_num
  case $menu_num in
  1)
    install_xray_ws
    ;;
  2)
    read -rp "请输入UUID:" UUID
    modify_UUID
    restart_all
    ;;
  3)
    source '/etc/os-release'
    xray_uninstall
    ;;
  4)
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" - install
    restart_all
    ;;
  0)
    exit 0
    ;;
  *)
    print_error "请输入正确的数字"
    ;;
  esac
}
menu "$@"
