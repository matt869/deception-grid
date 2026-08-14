# Deploying on an Azure VM

A field-tested runbook for running the honeypot on a single Azure Ubuntu VM with
the real bait on ports 22/23/80/21, admin SSH moved out of the way, and the
dashboard reachable only through an SSH tunnel. This is the exact sequence used
to stand up the reference deployment.

> **Safety model in one line:** the honeypot lives entirely on the cloud VM;
> your workstation only ever makes *outbound* SSH connections to it. Attack
> traffic never reaches your local network. The one rule: don't download
> captured payloads to a machine you care about — inspect them via the dashboard.

---

## 0. Before you touch the VM — the Network Security Group

In the Azure portal, on the VM's NSG, create two inbound rules:

| Priority | Name | Source | Dest ports | Protocol | Action |
|---------:|------|--------|-----------|----------|--------|
| 300 | `Allow-Admin-SSH-62222` | **My IP** (your workstation) | `62222` | TCP | Allow |
| 310 | `Allow-Honeypot-Public` | `Any` | `22,23,80,21,6379,3306` | TCP | Allow |

Ports `6379` (Redis) and `3306` (MySQL) are the datastore bait — include them in
rule 310 (or add a second rule) so those services actually receive traffic. They
run inside the sensor either way, but the NSG must let the internet reach them.

**The admin rule's Source must be your own workstation IP — never `Any`.** An
admin SSH port open to the world defeats the point of moving it. Leave the
default `AllowVnetInBound` / `AllowAzureLoadBalancerInBound` / `DenyAll` rules
alone. Do **not** open 8080 or 8000 — the dashboard and API stay private.

Verify after the VM is running: **Networking → Effective security rules** should
list rules 300 and 310.

---

## 1. Connect and install Docker

```bash
ssh -i "path\to\honeypot-vm_key.pem" azureuser@<VM_PUBLIC_IP>

sudo apt update && sudo apt install -y git curl
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER          # full effect next login; use sudo meanwhile

git clone https://github.com/matt869/honeypot-dashboard.git
cd honeypot-dashboard
docker compose version                 # need v2.24+ for the override tags below
```

## 2. Move admin SSH to 62222 (so the honeypot can own port 22)

**Keep your current session open.** Add the NSG rule for 62222 *first* (step 0),
then:

```bash
sudo sed -i 's/^#\?Port 22$/Port 62222/' /etc/ssh/sshd_config
sudo systemctl stop ssh.socket 2>/dev/null; sudo systemctl disable ssh.socket 2>/dev/null
sudo systemctl restart ssh
sudo sshd -T | grep -i '^port'         # must print: port 62222
```

**In a new terminal**, confirm the new port works before closing the old one:

```powershell
ssh -i "path\to\honeypot-vm_key.pem" -p 62222 azureuser@<VM_PUBLIC_IP>
```

Only once that logs in are you safe to close the original session.

## 3. Docker log rotation (scanners are relentless)

```bash
sudo bash -c 'cat > /etc/docker/daemon.json' <<'EOF'
{ "log-driver": "json-file", "log-opts": { "max-size": "10m", "max-file": "3" } }
EOF
sudo systemctl restart docker
```

## 4. Port-mapping override

The committed `docker-compose.yml` publishes high ports and exposes the
dashboard/API. This override rebinds the bait to real low ports, keeps the
dashboard on localhost, and unpublishes the API. It needs Compose **v2.24+**
(for `!override` / `!reset`).

```bash
cat > docker-compose.override.yml <<'EOF'
services:
  sensor:
    ports: !override
      - "22:2222"     # ssh bait (real 22)
      - "23:2323"     # telnet bait
      - "80:8081"     # http bait
      - "21:2121"     # ftp bait
    volumes:
      - sensor_data:/app/data          # persist captured payloads + SSH host key
  api:
    ports: !reset []                   # internal only; nginx reaches it over the network
  dashboard:
    ports: !override
      - "127.0.0.1:8080:80"            # localhost only — reach via SSH tunnel

volumes:
  sensor_data:
EOF
```

**Validate the merged result before launching** — the dashboard must show
`host_ip: 127.0.0.1`, the sensor the low ports, the api no ports:

```bash
sudo docker compose config | grep -E 'host_ip|published|^  [a-z]+:'
```

## 5. Launch

```bash
sudo docker compose up -d --build      # first run builds 3 images, a few minutes
sudo docker compose ps                 # all should be Up / healthy
sudo ss -tlnp | grep -E ':22 |:23 |:80 |:21 |127.0.0.1:8080'
```

Expect `docker-proxy` on `0.0.0.0:22/23/80/21` and the dashboard on
`127.0.0.1:8080`.

## 6. Turn on automatic detection + scoring

The sensor records events, but nothing runs the detection rules or the attacker
scoring on its own. A small cron job keeps alerts and attacker profiles current
by calling the API (through the dashboard's nginx proxy, which is already on
localhost):

```bash
cat > ~/honeypot-cron.sh <<'EOF'
#!/usr/bin/env bash
# Re-run detection and rebuild attacker aggregates. Both are idempotent.
curl -fsS -X POST "http://localhost:8080/api/alerts/run?hours=24"   >/dev/null 2>&1
curl -fsS -X POST "http://localhost:8080/api/attackers/rebuild"     >/dev/null 2>&1
EOF
chmod +x ~/honeypot-cron.sh
( crontab -l 2>/dev/null; echo "*/5 * * * * $HOME/honeypot-cron.sh" ) | crontab -
```

Detection now runs every 5 minutes. Trigger it once immediately:

```bash
~/honeypot-cron.sh && echo "first detection run done"
```

## 6b. Operational upgrades (optional but recommended)

**Real-time alerting** — set a webhook so new high-severity alerts page you.
Create a `.env` next to `docker-compose.yml` and recreate the API:

```bash
echo 'ALERT_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ' >> .env
echo 'ALERT_MIN_SEVERITY=high' >> .env
sudo docker compose up -d api
```

Slack/Discord/Teams/generic are auto-detected from the URL.

**Threat-intel feeds** — load real blocklists so `known-bad`/high-score matches
fire (the sensor mounts `data/indicators/` read-only; a weekly cron refreshes):

```bash
python3 -m tools.refresh_indicators --defaults   # blocklist.de + ipsum + firehol
sudo docker compose restart sensor               # pick up the new indicators
```

**IOC export** — pull deployable indicators any time (also written hourly to
`exports/` by cron):

```bash
curl "http://localhost:8080/api/export/blocklist?min_score=60"
curl "http://localhost:8080/api/export/stix?min_score=60"
```

**Backups / retention / fail2ban** — nightly `pg_dump` (7-day rotation), 45-day
event pruning, and a `fail2ban` sshd jail on port 62222 are installed as host
cron jobs and a systemd service. Adjust the schedules in `crontab -l`.

## 7. View the dashboard (SSH tunnel)

From your **workstation**, in a window you leave open:

```powershell
ssh -i "path\to\honeypot-vm_key.pem" -p 62222 -L 8080:localhost:8080 azureuser@<VM_PUBLIC_IP>
```

Then browse **http://localhost:8080**. Tunnel window open = dashboard reachable;
close it and the dashboard is unreachable to everyone, including you. That's the
intended security posture.

---

## Optional: light up the world map (GeoLite2)

Geolocation is off until you supply a **MaxMind GeoLite2** database — it's free
but licensed, so it can't ship in the repo. With a free MaxMind account and
license key:

```bash
# on the VM
KEY=<your_maxmind_license_key>
curl -L "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=$KEY&suffix=tar.gz" \
  | tar -xz --strip-components=1 -C data/geolite2 --wildcards '*/GeoLite2-City.mmdb'
curl -L "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=$KEY&suffix=tar.gz" \
  | tar -xz --strip-components=1 -C data/geolite2 --wildcards '*/GeoLite2-ASN.mmdb'

# rebuild the sensor so geoip2 gets installed, then restart
sed -i 's#"paramiko>=3.4"#"paramiko>=3.4" "geoip2>=4.8"#' honeypot/Dockerfile
sudo docker compose up -d --build sensor api
```

Country/city/ASN and the map populate from the next events on. Until then, geo
fields read `unavailable` — the sensor never guesses a location.

---

## Operations

```bash
# always: SSH in on 62222, then cd honeypot-dashboard
sudo docker compose ps                       # status
sudo docker compose logs -f sensor           # watch captures live
sudo docker compose logs --tail 100 api      # API logs
sudo docker compose restart sensor           # restart a service
sudo docker compose down                     # stop all (Postgres + payloads persist in volumes)
sudo docker compose up -d                    # start again
sudo docker compose pull && \
  git pull && sudo docker compose up -d --build   # update to latest code
```

**Data handling:** captured credentials and payloads are sensitive and often
real — see [FINDINGS.md](../FINDINGS.md). Set `API_REDACT_PASSWORDS=1` (in the
`api` service environment) if anyone beyond you will see the dashboard.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `ERR_CONNECTION_REFUSED` at localhost:8080 | The SSH tunnel isn't running. Open the step-7 command and leave it open. |
| `sensor`/`api` restarting, `ModuleNotFoundError: psycopg2` | Old images without the Postgres driver — `git pull && docker compose up -d --build`. |
| No alerts / empty Attackers page | Detection isn't running — set up the step-6 cron, or click "Re-run detection" in the dashboard. |
| Locked out after the SSH move | NSG rule 300 for 62222 missing or Source wrong; recover via the Azure **Serial console**. |
| `!override`/`!reset` errors | Compose older than v2.24 — upgrade it, or edit `docker-compose.yml` ports directly. |
