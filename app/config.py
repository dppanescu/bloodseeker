# app/config.py
from __future__ import annotations
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import BaseModel, Field, AliasChoices
from typing import List, Optional
try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:
    import tomli as tomllib  # Python 3.10 fallback
import pathlib

CONFIG_PATHS = [
    "/etc/brandmon/brandmon.toml",
    str(pathlib.Path(__file__).resolve().parents[1] / "config" / "brandmon.toml"),
]

class AppSettings(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False
    base_url: str = "http://localhost:8080"

class DatabaseSettings(BaseModel):
    url: str = "postgresql+psycopg2://brandmon:schimba-parola@localhost:5432/brandmon"

class RedisSettings(BaseModel):
    url: str = "redis://localhost:6379/0"

class SecuritySettings(BaseModel):
    csp: str = "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; form-action 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; connect-src 'self'; media-src 'none'; worker-src 'self' blob:'self'"
    hsts_enabled: bool = True
    referrer_policy: str = "no-referrer"

class AlertsSettings(BaseModel):
    email_enabled: bool = False
    smtp_host: str = "localhost"
    smtp_port: int = 25
    smtp_starttls: bool = False
    smtp_from: str = "brandmon@localhost"
    smtp_to: List[str] = ["security@example.com"]

    splunk_hec_enabled: bool = False
    splunk_hec_url: str = ""
    splunk_hec_source: str = "brandmon"
    splunk_hec_sourcetype: str = "brandmon:event"

    teams_enabled: bool = False
    teams_webhook_url: str = ""

class ScoringSettings(BaseModel):
    alert_threshold: int = 70

class DnstwistSettings(BaseModel):
    path: str = "/usr/bin/dnstwist"
    enabled: bool = True
    timeout_sec: int = 600
    max_variants: int = 2000
    threads: int = 16
    nameservers: list[str] = []        # ["1.1.1.1","8.8.8.8","https://dns.google/dns-query"]
    fuzzers: list[str] = []            # dacă e gol -> preset extins în task

    # Enrich
    banners_enabled: bool = True
    mxcheck_enabled: bool = True
    whois_enabled: bool = False        # lăsăm oprit

    lsh_enabled: bool = False
    lsh_algo: str = "tlsh"             # "ssdeep" | "tlsh"
    lsh_url: str | None = None         # ideal homepage-ul brandului

    phash_enabled: bool = False
    screenshots_dir: str | None = "/var/log/brandmon/screens"

# --- ADĂUGAT: setări WHOIS ---
class WhoisSettings(BaseModel):
    enabled: bool = True          # master switch
    timeout_sec: int = 15         # timeout HTTP către whoisxmlapi
    ttl_hours: int = 24           # TTL hard pentru cache
    swr_hours: int = 6            # soft window refresh (dacă îl folosești)
    cooldown_sec: int = 600       # rate limit simplu per domeniu
# ------------------------------

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="BRANDMON_", env_file=None, extra="ignore")

    app: AppSettings = AppSettings()
    database: DatabaseSettings = DatabaseSettings()
    redis: RedisSettings = RedisSettings()
    security: SecuritySettings = SecuritySettings()
    alerts: AlertsSettings = AlertsSettings()
    scoring: ScoringSettings = ScoringSettings()
    dnstwist: DnstwistSettings = DnstwistSettings()
    whois: WhoisSettings = WhoisSettings()

    # Secrets (env-only). Acceptă ATÂT WHOISXML_API_KEY, cât și BRANDMON_WHOISXML_API_KEY.
    WHOISXML_API_KEY: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("WHOISXML_API_KEY", "BRANDMON_WHOISXML_API_KEY"),
    )
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SPLUNK_HEC_TOKEN: Optional[str] = None

def load_settings() -> Settings:
    data: dict = {}
    for pth in CONFIG_PATHS:
        try:
            with open(pth, "rb") as f:
                file_data = tomllib.load(f)
                # Valorile din fișiere au prioritate mică față de ENV
                data = file_data | data
        except FileNotFoundError:
            continue
    return Settings(**data)

settings = load_settings()
