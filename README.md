# Anti Ban-Evasion (ABE) by FiveHost

Système de corrélation forensique multi-couches conçu pour détecter et neutraliser les doubles comptes et contournements de bannissements sur serveurs Minecraft (Paper/Purpur), même derrière un VPN ou un proxy résidentiel.

---

## 🚀 Installation Rapide (Debian 11 / 12 / 13)

Exécutez cette commande en `root` sur votre machine hôte :

```bash
git clone [https://github.com/FiveHost/anti-ban-evasion.git](https://github.com/FiveHost/anti-ban-evasion.git) /opt/corvus-sentinel
cd /opt/corvus-sentinel
chmod +x install.sh && ./install.sh
```

Le script installe les dépendances, initialise la base SQLite, compile le plugin Java et configure les services `systemd`.

---

## 🛠 Architecture & Fonctionnement

ABE combine 3 composants indépendants :

1. **Passive Sniffer (Scapy / Raw Socket) :** 
   Écoute passivement le trafic réseau sans ralentir le serveur de jeu. Il extrait les métriques du paquet TCP SYN (TTL, Window Size, MSS, Window Scale) et intercepte les canaux de mods déclarés via `minecraft:register`.
2. **Paper / Purpur Plugin (`AntiBanEvasion.jar`) :** 
   Collecte la télémétrie in-game (Client Brand, langue, render distance, skin model mask) et mesure la dérive d'horloge Quartz matérielle (NTP Skew) lors des interactions de chat.
3. **Moteur de Corrélation & Web Dashboard (FastAPI + Tailwind + Cytoscape.js) :** 
   Centralise la télémétrie, calcule le score de recoupement sur 100% et modélise les liaisons sous forme de graphe interactif.

---

## 📊 Matrice d'Attribution des Points

| Vecteur Analysé | Pondération | Condition d'attribution |
| :--- | :---: | :--- |
| **Adresse IP Partagée** | **+60 %** | Même IP directe ou trouvée dans l'historique commun (déclenchement instantané). |
| **Options Atypiques (`options.txt`)** | **+25 %** | Render distance extrême ($\ge 28\text{ ch}$) ou personnalisée + même langue (0% sur réglages d'usine). |
| **Launcher / Client Brand** | **+10 %** | Même loader ou client personnalisé (Dawn, Feather, Lunar, etc.). |
| **Horloge Quartz (NTP Skew)** | **+5 %** | Écart de dérive matérielle $\vert{}\Delta\vert{} \le 3.5\text{ ms}$ (corroboration même PC). |
| **Fournisseur Réseau (ASN)** | **+5 %** | Même opérateur télécom ou même infrastructure VPN. |
| **Stack TCP OS** | **+5 %** | Même signature noyau (Windows `65535:8` ou Linux). |

> **Seuil d'alerte global : 40 %**  
> Ce seuil permet d'attraper les alts sous VPN dès 3 concordances matérielles/options, tout en garantissant 0 faux positif sur les joueurs innocents utilisant le même launcher.

---

## 🔌 Intégration sur les Serveurs Minecraft

1. Rendez-vous sur votre dashboard ABE (`http://VOTRE_IP:8000`).
2. Cliquez sur le bouton **« Plugin .JAR »** pour télécharger le fichier compilé.
3. Placez `AntiBanEvasion.jar` dans le dossier `plugins/` de votre serveur Paper/Purpur.
4. Si le serveur tourne dans un conteneur Docker (ex: Pterodactyl), vérifiez que l'IP de la passerelle Docker (`172.18.0.1` ou `172.17.0.1`) correspond bien à la variable `api-url` dans `plugins/AntiBanEvasion/config.yml`.
5. Redémarrez le serveur.

---

## ⚙ Gestion des Services

```bash
# Vérifier l'état de l'API Web
systemctl status sentinel-api

# Vérifier l'état du Sniffer Réseau
systemctl status sentinel-sniffer

# Consulter les logs en temps réel
journalctl -u sentinel-api -f
journalctl -u sentinel-sniffer -f
```# abe
Anti Ban Evasion for Minecraft
