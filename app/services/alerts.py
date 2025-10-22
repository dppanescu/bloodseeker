from __future__ import annotations
from typing import Optional, Dict, Any, List
from . import scoring as scoring_mod
from ..config import settings
import smtplib, ssl, json, http.client, urllib.request

def send_email(subject: str, body: str):
    if not settings.alerts.email_enabled:
        return
    msg = f"""From: {settings.alerts.smtp_from}
To: {', '.join(settings.alerts.smtp_to)}
Subject: {subject}

{body}
"""
    context = ssl.create_default_context()
    with smtplib.SMTP(settings.alerts.smtp_host, settings.alerts.smtp_port) as server:
        if settings.alerts.smtp_starttls:
            server.starttls(context=context)
        if settings.SMTP_USERNAME and settings.SMTP_PASSWORD:
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        server.sendmail(settings.alerts.smtp_from, settings.alerts.smtp_to, msg.encode('utf-8'))

def send_splunk_hec(event: Dict[str, Any]):
    if not settings.alerts.splunk_hec_enabled or not settings.alerts.splunk_hec_url or not settings.SPLUNK_HEC_TOKEN:
        return
    data = json.dumps({
        "event": event,
        "source": settings.alerts.splunk_hec_source,
        "sourcetype": settings.alerts.splunk_hec_sourcetype
    }).encode("utf-8")
    req = urllib.request.Request(settings.alerts.splunk_hec_url, data=data, headers={
        "Authorization": f"Splunk {settings.SPLUNK_HEC_TOKEN}",
        "Content-Type": "application/json"
    })
    urllib.request.urlopen(req, timeout=5)

def send_teams(text: str):
    if not settings.alerts.teams_enabled or not settings.alerts.teams_webhook_url:
        return
    data = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(settings.alerts.teams_webhook_url, data=data, headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=5)

def fanout_alert(subject: str, body: str, event: dict):
    send_email(subject, body)
    send_splunk_hec(event)
    send_teams(f"{subject}\n\n{body[:4000]}")
