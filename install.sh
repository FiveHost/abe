cat << 'EOF' > install.sh
#!/usr/bin/env bash
# ==============================================================================
#  Anti Ban-Evasion (ABE) by FiveHost
#  Script de Déploiement Automatisé - Debian 12 (Bookworm) Compatible
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}====================================================${NC}"
echo -e "${BLUE}   Déploiement Anti Ban-Evasion (ABE) - FiveHost   ${NC}"
echo -e "${BLUE}====================================================${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Ce script doit être exécuté en tant que root.${NC}"
    exit 1
fi

# Détection automatique du répertoire courant ou chemin FiveHost par défaut
INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ "$INSTALL_DIR" == "/" ] || [ "$INSTALL_DIR" == "/root" ]; then
    INSTALL_DIR="/opt/fivehost-abe"
fi

DATA_DIR="${INSTALL_DIR}/data"
BACKEND_DIR="${INSTALL_DIR}/backend"
FRONTEND_DIR="${INSTALL_DIR}/frontend"
BUILD_DIR="/tmp/abe-build"

echo -e "${GREEN}[1/7] Installation des dépendances Bookworm sans interruption de service...${NC}"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
    python3 python3-pip python3-venv sqlite3 tcpdump \
    default-jdk maven curl git libpcap-dev

echo -e "${GREEN}[2/7] Préparation des répertoires de travail...${NC}"
mkdir -p "${DATA_DIR}" "${BACKEND_DIR}" "${FRONTEND_DIR}" "${BUILD_DIR}/src/main/java/fr/fivehost/abe" "${BUILD_DIR}/src/main/resources"

echo -e "${GREEN}[3/7] Configuration de l'environnement virtuel Python...${NC}"
if [ ! -d "${INSTALL_DIR}/venv" ]; then
    python3 -m venv "${INSTALL_DIR}/venv"
fi
"${INSTALL_DIR}/venv/bin/pip" install --upgrade pip --quiet
"${INSTALL_DIR}/venv/bin/pip" install fastapi uvicorn pydantic scapy requests --quiet

echo -e "${GREEN}[4/7] Initialisation de la Base de Données SQLite...${NC}"
sqlite3 "${DATA_DIR}/sentinel.db" << 'EOFDB'
CREATE TABLE IF NOT EXISTS monitored_servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    port INTEGER UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS telemetry (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    server_port INTEGER,
    username TEXT,
    uuid TEXT,
    ip TEXT,
    src_port INTEGER,
    ttl INTEGER,
    hops INTEGER,
    mss INTEGER,
    win_size INTEGER,
    wscale INTEGER,
    client_brand TEXT,
    locale TEXT,
    view_distance INTEGER,
    skin_mask INTEGER,
    main_hand TEXT,
    ping_ms INTEGER,
    clock_offset_ms REAL,
    channels_hash TEXT,
    raw_channels TEXT
);

CREATE INDEX IF NOT EXISTS idx_telemetry_user ON telemetry(username);
CREATE INDEX IF NOT EXISTS idx_telemetry_ip ON telemetry(ip);
CREATE INDEX IF NOT EXISTS idx_telemetry_port ON telemetry(server_port);

INSERT OR IGNORE INTO monitored_servers (name, port) VALUES ('Serveur Principal', 25565);
EOFDB

echo -e "${GREEN}[5/7] Compilation du plugin Paper / Purpur (Java 17 / Compatible 21)...${NC}"
cat << 'EOFPOM' > "${BUILD_DIR}/pom.xml"
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>fr.fivehost.abe</groupId>
    <artifactId>AntiBanEvasion</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>
    <properties>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>
    <repositories>
        <repository>
            <id>papermc</id>
            <url>https://repo.papermc.io/repository/maven-public/</url>
        </repository>
    </repositories>
    <dependencies>
        <dependency>
            <groupId>io.papermc.paper</groupId>
            <artifactId>paper-api</artifactId>
            <version>1.20.4-R0.1-SNAPSHOT</version>
            <scope>provided</scope>
        </dependency>
    </dependencies>
</project>
EOFPOM

cat << 'EOFPLUGIN' > "${BUILD_DIR}/src/main/resources/plugin.yml"
name: AntiBanEvasion
version: 1.0.0
main: fr.fivehost.abe.AntiBanEvasion
api-version: '1.20'
author: FiveHost
EOFPLUGIN

cat << 'EOFJAVA' > "${BUILD_DIR}/src/main/java/fr/fivehost/abe/AntiBanEvasion.java"
package fr.fivehost.abe;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.Listener;
import org.bukkit.event.player.AsyncPlayerChatEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.plugin.java.JavaPlugin;

import java.net.HttpURLConnection;
import java.net.URL;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

public class AntiBanEvasion extends JavaPlugin implements Listener {

    private String apiUrl;

    @Override
    public void onEnable() {
        saveDefaultConfig();
        this.apiUrl = getConfig().getString("api-url", "http://172.18.0.1:8000/api/plugin");
        Bukkit.getPluginManager().registerEvents(this, this);
        getLogger().info("ABE (Anti Ban-Evasion by FiveHost) actif !");
    }

    @EventHandler
    public void onJoin(PlayerJoinEvent event) {
        Player p = event.getPlayer();
        Bukkit.getScheduler().runTaskLater(this, () -> {
            try {
                String brand = p.getClientBrandName() != null ? p.getClientBrandName() : "Vanilla";
                String locale = p.locale().getLanguage() + "_" + p.locale().getCountry().toLowerCase();
                int viewDist = p.getClientViewDistance();
                int bitmask = 127;
                int ping = p.getPing();
                String ip = p.getAddress().getAddress().getHostAddress();
                int srcPort = p.getAddress().getPort();
                int srvPort = Bukkit.getPort();

                String json = String.format(
                    "{\"server_port\":%d,\"username\":\"%s\",\"uuid\":\"%s\",\"ip\":\"%s\",\"src_port\":%d,\"client_brand\":\"%s\",\"locale\":\"%s\",\"view_distance\":%d,\"skin_mask\":%d,\"main_hand\":\"%s\",\"ping_ms\":%d}",
                    srvPort, p.getName(), p.getUniqueId().toString(), ip, srcPort, brand, locale, viewDist, bitmask, p.getMainHand().name(), ping
                );

                sendPost(apiUrl + "/join", json);
            } catch (Exception e) {
                getLogger().warning("Erreur Join ABE: " + e.getMessage());
            }
        }, 30L);
    }

    @EventHandler
    public void onChat(AsyncPlayerChatEvent event) {
        Player p = event.getPlayer();
        long clientTime = System.currentTimeMillis();
        long serverTime = System.currentTimeMillis();
        int ping = p.getPing();
        int srvPort = Bukkit.getPort();

        String json = String.format(
            "{\"server_port\":%d,\"username\":\"%s\",\"client_timestamp_ms\":%d,\"server_timestamp_ms\":%d,\"ping_ms\":%d}",
            srvPort, p.getName(), clientTime, serverTime, ping
        );

        sendPost(apiUrl + "/clock", json);
    }

    private void sendPost(String endpoint, String json) {
        Bukkit.getScheduler().runTaskAsynchronously(this, () -> {
            try {
                URL url = new URL(endpoint);
                HttpURLConnection con = (HttpURLConnection) url.openConnection();
                con.setRequestMethod("POST");
                con.setRequestProperty("Content-Type", "application/json");
                con.setDoOutput(true);
                con.setConnectTimeout(2000);
                con.setReadTimeout(2000);

                try (OutputStream os = con.getOutputStream()) {
                    os.write(json.getBytes(StandardCharsets.UTF_8));
                }
                con.getResponseCode();
            } catch (Exception ignored) {}
        });
    }
}
EOFJAVA

cat << 'EOFCONF' > "${BUILD_DIR}/src/main/resources/config.yml"
# Passerelle par défaut pour conteneurs Pterodactyl/Docker
api-url: "http://172.18.0.1:8000/api/plugin"
EOFCONF

cd "${BUILD_DIR}"
mvn clean package -q
cp "${BUILD_DIR}/target/AntiBanEvasion-1.0.0.jar" "${INSTALL_DIR}/AntiBanEvasion.jar"
cd "${INSTALL_DIR}"

echo -e "${GREEN}[6/7] Configuration des services isolés systemd...${NC}"

cat << EOFAPI > /etc/systemd/system/sentinel-api.service
[Unit]
Description=FiveHost ABE FastAPI Web & Forensics Engine
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${BACKEND_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/uvicorn api:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOFAPI

cat << EOFSNIFF > /etc/systemd/system/sentinel-sniffer.service
[Unit]
Description=FiveHost ABE Passive TCP & Mod Channels Sniffer
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${BACKEND_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python3 ${BACKEND_DIR}/sniffer.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOFSNIFF

systemctl daemon-reload
systemctl enable sentinel-api sentinel-sniffer
systemctl restart sentinel-api sentinel-sniffer

echo -e "${GREEN}[7/7] Déploiement terminé sans perturbation !${NC}"
echo -e "${BLUE}====================================================${NC}"
echo -e "Dashboard accessible sur : ${GREEN}http://$(curl -s https://api.ipify.org):8000${NC}"
echo -e "Plugin .JAR prêt dans : ${GREEN}${INSTALL_DIR}/AntiBanEvasion.jar${NC}"
echo -e "${BLUE}====================================================${NC}"
EOF
chmod +x install.sh
