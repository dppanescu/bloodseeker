# BrandMon — Domain Impersonation Monitor

Monitor pentru impersonarea domeniilor și brandurilor: colectează „seed domains”, generează variante (fuzzing simplu + DNSTwist), rulează probe DNS/HTTP, normalizează WHOIS, calculează scor de risc și trimite alerte (Email, Splunk HEC, Microsoft Teams). UI cu FastAPI + Jinja2 + HTMX. Queue & scheduling cu Celery (Redis).

## Stack
- API/UI: FastAPI + Jinja2 + HTMX
- DB: PostgreSQL (SQLAlchemy + Alembic)
- Queue: Celery (Redis broker & backend), Celery Beat
- Probes: dnspython (DNS), httpx (HTTP), dnstwist (opțional)
- Servicii: WhoIsXML API, alerte email / Splunk HEC / Teams
- Logging: JSON (fallback text) în `/var/log/brandmon/brandmon.log`

## Instalare rapidă
Vezi `config/brandmon.toml` pentru setări implicite. Secretele (ex. `WHOISXML_API_KEY`, `SPLUNK_HEC_TOKEN`, `SMTP_PASSWORD`) vin din ENV (ex. `/etc/brandmon/brandmon.env`).

### Migrații DB
```bash
export DATABASE_URL="postgresql+psycopg2://brandmon:PAROLA@localhost:5432/brandmon"
alembic upgrade head
```

### Servicii (systemd)
În `deploy/systemd` găsești unit-urile pentru API, worker, beat și certstream.
Logrotate exemplu: `deploy/logrotate/brandmon`.

## Endpoint-uri
- `/` — ping JSON
- `/dashboard` — KPI + ultimele scanări
- `/seeds`, `/seeds/{id}` — management seed-uri + generare variante
- `/variants/{id}` — detaliu variantă, probe, WHOIS, scor
- `/health/`, `/health/api` — sănătate
- `/metrics` — metrici simple în format text (Prometheus-like)

## Note de producție
- Configurează Nginx pentru TLS, HSTS, CSP (dacă le gestionezi acolo).
- Celery: `worker_prefetch_multiplier=1`, `task_acks_late=True`, `task_reject_on_worker_lost=True`.
- Probe HTTP reusesc un client global httpx pentru performanță.
- Alembic citește `DATABASE_URL` din ENV; `alembic.ini` nu mai conține parole.
