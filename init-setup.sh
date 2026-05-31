#!/bin/bash

# Update System
apt update -y
apt upgrade -y

# Install Docker
bash <(curl -sSL https://get.docker.com)

# UFW settings
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 47153

# Panel ports
ufw allow 2053
ufw allow 45153

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

# Certbot for 3x-UI
DOMAIN="vpn.entcloud.ru"
apt-get install certbot -y
certbot certonly --standalone --agree-tos --register-unsafely-without-email -d $DOMAIN
certbot renew --dry-run
