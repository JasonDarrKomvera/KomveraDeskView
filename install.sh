#!/usr/bin/env bash
set -e

APP_DIR="/opt/komvera-deskview"
SERVICE_NAME="komvera-deskview"
GIT_REPO="https://github.com/JasonDarrKomvera/KomveraDeskView.git"

echo "==> System wird vorbereitet..."
sudo apt update
sudo apt install -y curl git

if ! command -v node >/dev/null 2>&1; then
    echo "==> Node.js wird installiert..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt install -y nodejs
fi

echo "==> Installiere App..."
sudo mkdir -p "$APP_DIR"
sudo chown -R $USER:$USER "$APP_DIR"

if [ -d "$APP_DIR/.git" ]; then
    cd "$APP_DIR"
    git pull
else
    git clone "$GIT_REPO" "$APP_DIR"
fi

cd "$APP_DIR"
npm install --omit=dev

sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null <<EOF
[Unit]
Description=Komvera DeskView
After=network.target

[Service]
WorkingDirectory=${APP_DIR}
ExecStart=/usr/bin/node ${APP_DIR}/server.js
Restart=always
User=${USER}

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable ${SERVICE_NAME}
sudo systemctl restart ${SERVICE_NAME}

echo "✅ Installation fertig"