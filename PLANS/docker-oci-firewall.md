# Docker sur OCI : Bonnes pratiques firewall

## Problème identifié
OCI empêche les accès root aux tables iptables nft. Docker utilise iptables-nft par défaut.

## Solution : Passer à iptables-legacy

### 1. Configuration système
```bash
# Vérifier les alternatives disponibles
update-alternatives --list iptables
# /usr/sbin/iptables-legacy
# /usr/sbin/iptables-nft

# Passer définitivement à iptables-legacy
sudo update-alternatives --set iptables /usr/sbin/iptables-legacy
sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
sudo update-alternatives --set arptables /usr/sbin/arptables-legacy
sudo update-alternatives --set ebtables /usr/sbin/ebtables-legacy

# Vérifier
iptables --version  # Doit afficher (legacy) pas (nf_tables)
```

### 2. Alternative : rootless Docker
```bash
# Installer rootless Docker (contourne iptables root)
curl -fsSL https://get.docker.com/rootless | sh
export PATH=$HOME/bin:$PATH
systemctl --user start docker
```

### 3. Architecture sécurisée (recommandé)

```
Internet
    ↓
OCI Security Lists (FW niveau cloud)
    ↓
Apache Reverse Proxy (port 80/443)
    ↓
Docker --network=host (port 8000 interne)
    ↓
API FastAPI (bind 127.0.0.1 pour services internes)
```

### 4. docker-compose.yml sécurisé
```yaml
version: '3.8'
services:
  dashboard-api:
    build:
      context: .
      dockerfile: Dockerfile.api
    network_mode: host  # OCI compliant
    ports: []  # Pas de ports exposés - utilise host
    environment:
      - API_HOST=127.0.0.1  # Pas 0.0.0.0
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
```

### 5. Validation post-setup
```bash
# Vérifier l'isolation
nmap -p 5432,8000,2222 158.178.206.226

# Doit retourner :
# 5432 : closed (Postgres pas exposé)
# 8000 : filtered (accessible via Apache uniquement)
# 2222 : open (Cowrie honeypot)
```

### 6. Checklist sécurité
- [ ] iptables-legacy configuré
- [ ] Security Lists OCI autorisent uniquement 80/443/2222
- [ ] Apache reverse proxy avec Rate limiting
- [ ] API bind 127.0.0.1 pour services internes
- [ ] Pas de conteneur DB sur la même instance
- [ ] Audits logs iptables activés