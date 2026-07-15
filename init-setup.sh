#!/bin/bash
set -Eeuo pipefail

# Enter values for settings
SSH_PORT=12345
TG_BOT_TOKEN=1234567890:AAEXAMPLE_BOT_TOKEN_xxxxxxxxxxxxx
TG_CHAT_ID=123456789
EXTERNAL_IP=$(curl -s -4 --max-time 10 ipv4.icanhazip.com || curl -s -4 --max-time 10 ifconfig.me || echo "")
PAM_NOTIFY_SCRIPT="/usr/local/libexec/ssh-login-telegram.sh"
PAM_NOTIFY_LOG="/var/log/ssh-login-telegram.log"
PAM_NOTIFY_LOGROTATE="/etc/logrotate.d/ssh-login-telegram"

### Functions
backup_file() {
  local f="$1"
  [[ -f "$f" ]] && cp -a "$f" "${f}.bak.$(date +%F-%H%M%S)"
}

set_sshd_option() {
  local key="$1"
  local value="$2"
  local file="$3"

  if grep -Eq "^[#[:space:]]*${key}[[:space:]]+" "$file"; then
    sed -ri "s|^[#[:space:]]*${key}[[:space:]]+.*|${key} ${value}|g" "$file"
  else
    echo "${key} ${value}" >> "$file"
  fi
}

### Execution

[[ "${EUID}" -eq 0 ]] || die "[!] Run this script as root"

if [[ -z "$EXTERNAL_IP" ]]; then
  read -rsp "Enter server's public IP: " EXTERNAL_IP
  echo
fi

# Create new user
read -rp "Enter username: " USERNAME
echo
if id "$USERNAME" >/dev/null 2>&1; then
 echo "[+] User $USERNAME already exists"
else
  echo "[+] Creating user $USERNAME"
  useradd -m -s /bin/bash "$USERNAME"
  passwd "$USERNAME"
  echo "[+] Adding user $USERNAME to sudo group"
  usermod -aG sudo "$USERNAME"
fi

### Update System & Install required packages
export DEBIAN_FRONTEND=noninteractive
apt update -y
apt upgrade -y
apt install -y ufw fail2ban curl ca-certificates libpam-modules logrotate

### Install Docker
bash <(curl -sSL https://get.docker.com)
usermod -aG docker "$USERNAME"

### UFW settings
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow $SSH_PORT
# Panel ports
ufw allow 2053
ufw allow 45153
# Subscriptions port
ufw allow 45196
# Amnezia ports
ufw allow 53
ufw allow 25222
ufw allow 25401
# 3x-ui ports
ufw allow 27600:27620/tcp
ufw allow 27600:27620/udp
ufw allow 46015:46020/udp
ufw allow 46015:46020/tcp
ufw allow https
ufw allow http
ufw enable
ufw status verbose

### Certbot for 3x-UI
DOMAIN="vpn.entcloud.ru"
apt-get install certbot -y
certbot certonly --standalone --agree-tos --register-unsafely-without-email -d $DOMAIN
certbot renew --dry-run

### Configure SSH
echo "[+] Configuring SSH"
SSHD_CONFIG="/etc/ssh/sshd_config"
backup_file "$SSHD_CONFIG"
set_sshd_option "Port" "$SSH_PORT" "$SSHD_CONFIG"
set_sshd_option "PermitRootLogin" "no" "$SSHD_CONFIG"
set_sshd_option "PasswordAuthentication" "yes" "$SSHD_CONFIG"
set_sshd_option "PubkeyAuthentication" "yes" "$SSHD_CONFIG"
set_sshd_option "ChallengeResponseAuthentication" "no" "$SSHD_CONFIG"
set_sshd_option "UsePAM" "yes" "$SSHD_CONFIG"
mkdir -p /run/sshd
chmod 755 /run/sshd

echo "[+] Validating sshd config"
sshd -t || die "[!] sshd config test failed"

echo "[+] Changing SSH socket config"
SSH_SOCKET_CONFIG=$(realpath /etc/systemd/system/sockets.target.wants/ssh.socket)
backup_file "$SSH_SOCKET_CONFIG"
sed -i "s/:22$/:$SSH_PORT/" $SSH_SOCKET_CONFIG
systemctl daemon-reload

### Configure fail2ban
echo "[+] Configuring fail2ban"
mkdir -p /etc/fail2ban
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
backend = systemd
banaction = ufw

[sshd]
enabled = true
port = ${SSH_PORT}
logpath = %(sshd_log)s
EOF

systemctl enable fail2ban
systemctl restart fail2ban

### Telegram SSH Notification
echo "[+] Installing Telegram SSH login notification hook"
install -d -m 700 /usr/local/libexec

cat > "$PAM_NOTIFY_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

LOG_FILE="/var/log/ssh-login-telegram.log"

log_msg() {
  local level="$1"
  shift
  local message="$*"
  local ts
  ts="$(date '+%F %T %Z')"
  printf '%s [%s] %s\n' "$ts" "$level" "$message" >> "$LOG_FILE"
  if command -v logger >/dev/null 2>&1; then
    logger -t ssh-login-telegram "[$level] $message"
  fi
}

trap 'log_msg ERROR "Unhandled error at line $LINENO"' ERR

TG_BOT_TOKEN=__TG_BOT_TOKEN__
TG_CHAT_ID=__TG_CHAT_ID__
SERVER_IP=__EXTERNAL_IP__

if [[ -z "${TG_BOT_TOKEN:-}" ]]; then
  log_msg ERROR "TG_BOT_TOKEN is empty, skipping Telegram notification"
  exit 0
fi

if [[ -z "${TG_CHAT_ID:-}" ]]; then
  log_msg ERROR "TG_CHAT_ID is empty, skipping Telegram notification"
  exit 0
fi

USER_NAME="${PAM_USER:-unknown}"
RHOST="${PAM_RHOST:-unknown}"
SERVICE="${PAM_SERVICE:-unknown}"
EVENT="${PAM_TYPE:-unknown}"
TTY="${PAM_TTY:-unknown}"
HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"
SERVER_IP="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n1)"
DATE_STR="$(date '+%F %T %Z')"

TEXT="[!] SSH event
Host: ${HOSTNAME_FQDN}
Server IP: ${SERVER_IP:-unknown}
User: ${USER_NAME}
From: ${RHOST}
Service: ${SERVICE}
Event: ${EVENT}
TTY: ${TTY}
Time: ${DATE_STR}"

log_msg INFO "Sending Telegram notification for user=${USER_NAME} from=${RHOST} service=${SERVICE} tty=${TTY}"

response_file="$(mktemp)"
http_code="$({
  curl -sS -m 10 -o "$response_file" -w '%{http_code}' -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
    -d "chat_id=${TG_CHAT_ID}" \
    --data-urlencode "text=${TEXT}"
} 2>&1)" || curl_error="$?"

if [[ -n "${curl_error:-}" ]]; then
  response_body="$(tr '\n' ' ' < "$response_file" 2>/dev/null || true)"
  log_msg ERROR "curl failed with exit=${curl_error}; details=${http_code}; response=${response_body}"
  rm -f "$response_file"
  exit 0
fi

response_body="$(tr '\n' ' ' < "$response_file")"
rm -f "$response_file"

if [[ "$http_code" != "200" ]]; then
  log_msg ERROR "Telegram API returned http=${http_code}; response=${response_body}"
  exit 0
fi

if printf '%s' "$response_body" | grep -q '"ok":true'; then
  log_msg INFO "Telegram notification sent successfully"
else
  log_msg ERROR "Telegram API response did not confirm success; response=${response_body}"
fi

exit 0
EOF

sed -i "s|__TG_BOT_TOKEN__|\"$TG_BOT_TOKEN\"|" "$PAM_NOTIFY_SCRIPT"
sed -i "s|__TG_CHAT_ID__|\"$TG_CHAT_ID\"|" "$PAM_NOTIFY_SCRIPT"
sed -i "s|__EXTERNAL_IP__|\"$EXTERNAL_IP\"|" "$PAM_NOTIFY_SCRIPT"

chmod 700 "$PAM_NOTIFY_SCRIPT"
touch "$PAM_NOTIFY_LOG"
chmod 600 "$PAM_NOTIFY_LOG"

PAM_SSHD="/etc/pam.d/sshd"
backup_file "$PAM_SSHD"

if ! grep -Fq "$PAM_NOTIFY_SCRIPT" "$PAM_SSHD"; then
  echo "session optional pam_exec.so $PAM_NOTIFY_SCRIPT" >> "$PAM_SSHD"
fi

echo "[+] Restarting SSH service"

SSH_SERVICE=""
for svc in ssh sshd; do
  if systemctl cat "$svc" >/dev/null 2>&1; then
    SSH_SERVICE="$svc"
    break
  fi
done

if [[ -n "$SSH_SERVICE" ]]; then
  systemctl restart "$SSH_SERVICE"
  systemctl enable "$SSH_SERVICE" >/dev/null 2>&1 || true
else
  echo "[!] SSH unit not found via systemctl, trying service command"
  if service ssh status >/dev/null 2>&1; then
    service ssh restart
  elif service sshd status >/dev/null 2>&1; then
    service sshd restart
  else
    die "SSH service not found"
  fi
fi

### Configure logrotate
echo "[+] Configure logrotate"
cat > "$PAM_NOTIFY_LOGROTATE" <<EOF
${PAM_NOTIFY_LOG} {
  daily
  rotate 14
  missingok
  notifempty
  compress
  delaycompress
  create 0600 root root
}
EOF

### Final checks and info
echo "[+] Final checks"
fail2ban-client status sshd || echo "[!] fail2ban sshd status check failed"
ufw status verbose || echo "[!] ufw status check failed"

echo
echo "Done."
echo "New SSH port: ${SSH_PORT}"
echo "User with sudo: ${USERNAME}"
echo
echo "IMPORTANT:"
echo "1. Open a NEW terminal before closing the current session."
echo "2. Test login: ssh -p ${SSH_PORT} ${USERNAME}@${EXTERNAL_IP:-<unknown>}"
echo "3. Test sudo after login: sudo -v"
echo "4. Only after successful login close the current root session."
