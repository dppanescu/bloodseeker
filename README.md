# BrandMon (baseline)

A clean, production-lean baseline for BrandMon. Stack: FastAPI + Jinja2/HTMX, PostgreSQL, Redis, Celery (worker + beat), no Docker.
Integrations: CertStream seed (separate service), WhoIsXML (key via env), DNS/HTTP probes (timeouts), scoring, alerts (email/Splunk HEC/Teams), structured logging to `/var/log/brandmon` with safe fallback.

## Layout
```
brandmon_baseline/
├─ pyproject.toml
├─ README.md
├─ config/brandmon.toml               # sample config (no secrets)
├─ deploy/systemd/*.service           # unit files
├─ alembic.ini
├─ alembic/                           # migrations
│  ├─ env.py
│  └─ versions/0001_init.py
└─ app/
   ├─ __init__.py
   ├─ main.py
   ├─ config.py
   ├─ logging_setup.py
   ├─ db.py
   ├─ models.py
   ├─ schemas.py
   ├─ tasks.py
   ├─ probes/
   │  ├─ dns_probe.py
   │  └─ http_probe.py
   ├─ services/
   │  ├─ alerts.py
   │  ├─ certstream_consumer.py
   │  └─ scoring.py
   ├─ routers/
   │  ├─ dashboard.py
   │  ├─ seeds.py
   │  └─ variants.py
   ├─ templates/
   │  ├─ _partials/
   │  │  ├─ flash.html
   │  │  ├─ pagination.html
   │  │  └─ variants_table.html
   │  ├─ base.html
   │  ├─ dashboard.html
   │  ├─ seeds_list.html
   │  ├─ seed_detail.html
   │  └─ variant_detail.html
   └─ static/
      ├─ css/app.css
      └─ js/app.js
```

## Quickstart (Ubuntu, no Docker)
1. Create user and directories:
   ```bash
   sudo useradd -r -s /usr/sbin/nologin brandmon || true
   sudo mkdir -p /opt/brandmon /var/log/brandmon
   sudo chown -R brandmon:brandmon /opt/brandmon /var/log/brandmon
   ```

2. Python venv and install:
   ```bash
   cd /opt/brandmon
   python3.12 -m venv .venv
   source .venv/bin/activate
   pip install -U pip
   pip install .
   ```

3. Config:
   - Copy `config/brandmon.toml` to `/etc/brandmon/brandmon.toml` and adjust non-secret values.
   - Put secrets in `/etc/brandmon/brandmon.env` (WHOISXML_API_KEY, SMTP creds, Splunk HEC token, Teams webhook).
   - Alembic:
     ```bash
     alembic upgrade head
     ```

4. Systemd:
   ```bash
   sudo cp deploy/systemd/*.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable brandmon.service brandmon-celery.service brandmon-celerybeat.service brandmon-certstream.service
   sudo systemctl start brandmon.service brandmon-celery.service brandmon-celerybeat.service brandmon-certstream.service
   ```

## Notes
- Logs write to `/var/log/brandmon/*.log` with JSON lines. If not writable, fallback to `./brandmon.log`.
- CSP is strict by default; adjust `settings.security.csp` if you add third-party assets.
- No authentication yet; forms use a lightweight anti-CSRF token via signed value.
