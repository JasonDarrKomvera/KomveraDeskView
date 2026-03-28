#!/usr/bin/env bash
set -e

APP_DIR="/opt/komvera-deskview"
SERVICE_NAME="komvera-deskview"
GIT_REPO="https://github.com/JasonDarrKomvera/KomveraDeskView.git"
NODE_MAJOR="20"

echo "==> Prüfe System..."

if [ ! -f /etc/os-release ]; then
    echo "Nicht unterstütztes Linux-System."
    exit 1
fi

. /etc/os-release

echo "Erkanntes System: $PRETTY_NAME"

case "$ID" in
    ubuntu|debian|raspbian)
        echo "==> Debian-basiertes System erkannt"
        ;;
    *)
        echo "Dieses Installationsscript unterstützt aktuell nur Ubuntu, Debian und Raspberry Pi OS."
        exit 1
        ;;
esac

echo "==> System wird vorbereitet..."
sudo apt update
sudo apt install -y curl ca-certificates gnupg git

if ! command -v node >/dev/null 2>&1; then
    echo "==> Node.js wird installiert..."
    curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | sudo -E bash -
    sudo apt install -y nodejs
fi

echo "==> Node Version:"
node -v
npm -v

echo "==> Installiere Anwendung nach $APP_DIR..."
sudo mkdir -p "$APP_DIR"
sudo chown -R "$USER:$USER" "$APP_DIR"

if [ -d "$APP_DIR/.git" ]; then
    echo "==> Vorhandenes Repo gefunden, Update wird durchgeführt..."
    cd "$APP_DIR"
    git pull
else
    echo "==> Repo wird geklont..."
    git clone "$GIT_REPO" "$APP_DIR"
fi

cd "$APP_DIR"

echo "==> npm install läuft..."
npm install --omit=dev

mkdir -p public

echo "==> systemd Service wird erstellt..."
sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null <<EOF
[Unit]
Description=Komvera DeskView
After=network.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
ExecStart=/usr/bin/node ${APP_DIR}/server.js
Restart=always
RestartSec=5
User=${USER}
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

echo "==> Service wird aktiviert..."
sudo systemctl daemon-reload
sudo systemctl enable ${SERVICE_NAME}
sudo systemctl restart ${SERVICE_NAME}

echo ""
echo "✅ Installation fertig"
echo "Status prüfen mit:"
echo "sudo systemctl status ${SERVICE_NAME}"
echo ""
echo "Logs ansehen mit:"
echo "journalctl -u ${SERVICE_NAME} -f"