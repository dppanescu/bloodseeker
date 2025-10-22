from __future__ import annotations
from typing import Any, Optional

from ..config import settings

"""
Scoring normalizat 0..100, proporțional și etic:
- Dacă TOATE semnalele de risc sunt la maxim și NU există mitigări de legitimitate → scor 100.
- Dacă semnalele de risc sunt minime (sau absente) → scor 0 (chiar dacă există mitigări, acestea doar scad, nu cresc).
- Mitigările (SPF/DKIM/DMARC) reduc multiplicativ scorul de bază.

Formula:
  base = Σ(weight_i * feature_i_norm)  (suma greutăților = 100)
  final = round( base * (1 - Σ(mitig_i)) ), apoi tăiat în [0,100]

Unde feature_i_norm ∈ [0,1]; mitig_i ∈ [0,1] și suma lor este plafonată la 1.
"""

# -- Semnale pozitive (de risc) și greutăți (suma = 100)
WEIGHTS = {
    "dns_ok": 15,          # are rezoluție DNS
    "http": 15,            # HTTP 2xx/3xx; 401/403 parțial
    "sld_similarity": 20,  # similaritate mare (distanță mică)
    "tld_risky": 6,        # TLD cu risc
    "visual": 5,           # hyphen/digit în nume
    "mx": 10,              # MX prezent
    "whois_fresh": 10,     # vârstă mică WHOIS
    "ct_seen": 12,         # apariții în CT
    "fuzzer": 7,           # tip dnstwist
}
assert sum(WEIGHTS.values()) == 100

HIGH_RISK_TLDS = {"ru", "cn", "tk", "top", "gq", "cf"}
FUZZY_BONUS = {
    "homoglyph": 10,
    "bitsquatting": 10,
    "subdomain": 8,
    "hyphenation": 6,
    "omission": 6,
    "transposition": 6,
    "insertion": 6,
    "replacement": 6,
    "repetition": 4,
    "vowelswap": 4,
}
FUZZY_MAX = max(FUZZY_BONUS.values()) if FUZZY_BONUS else 1

# -- Mitigări de legitimitate (fracții multiplicative)
# Valori gândite astfel încât combinarea lor să poată reduce drastic riscul,
# dar fără să producă scor negativ. Suma este plafonată la 1.0.
MITIG_WEIGHTS = {
    "spf_present": 0.12,
    "dkim_present": 0.08,
    "dmarc_present": 0.05,
    "dmarc_policy_reject": 0.25,
    "dmarc_policy_quarantine": 0.15,
    "dmarc_policy_none": 0.08,
}


def _cap(x: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, x))


def _norm_http(http_status: Optional[int]) -> float:
    if http_status is None:
        return 0.0
    if 200 <= http_status < 400:
        return 1.0
    if http_status in (401, 403):
        return 0.3
    return 0.0


def _norm_sld_similarity(sld_distance: Optional[int]) -> float:
    if sld_distance is None:
        return 0.0
    if sld_distance <= 0:
        return 0.0  # identic cu seed-ul → tratăm ca non-variant
    if sld_distance == 1:
        return 1.0
    if sld_distance == 2:
        return 2/3
    if sld_distance == 3:
        return 1/3
    return 0.1  # >3: puțin risc rezidual


def _norm_whois_days(whois_days_old: Optional[int]) -> float:
    if whois_days_old is None:
        return 0.0
    if whois_days_old <= 7:
        return 1.0
    if whois_days_old <= 30:
        return 0.6
    return 0.0


def _norm_ct_seen(ct_seen_count: int) -> float:
    if ct_seen_count >= 5:
        return 1.0
    if ct_seen_count >= 1:
        return 0.7
    return 0.0


def _norm_fuzzer(fuzzer: Optional[str]) -> float:
    if not fuzzer:
        return 0.0
    return min(1.0, float(FUZZY_BONUS.get(fuzzer, 0)) / float(FUZZY_MAX))


def _mitigation_factor(*, spf_present: Optional[bool], dkim_present: Optional[bool],
                       dmarc_present: Optional[bool], dmarc_policy: Optional[str]) -> float:
    m = 0.0
    if spf_present:
        m += MITIG_WEIGHTS["spf_present"]
    if dkim_present:
        m += MITIG_WEIGHTS["dkim_present"]
    if dmarc_present:
        m += MITIG_WEIGHTS["dmarc_present"]
        pol = (dmarc_policy or "").lower()
        if "reject" in pol:
            m += MITIG_WEIGHTS["dmarc_policy_reject"]
        elif "quarantine" in pol:
            m += MITIG_WEIGHTS["dmarc_policy_quarantine"]
        elif "none" in pol:
            m += MITIG_WEIGHTS["dmarc_policy_none"]
    # plafonăm între 0 și 1
    m = max(0.0, min(1.0, m))
    return 1.0 - m


def compute_risk_score(
    *,
    domain: str,
    seed_sld: Optional[str] = None,
    dns_ok: Optional[bool] = None,
    http_status: Optional[int] = None,
    tld: Optional[str] = None,
    sld_distance: Optional[int] = None,
    ct_seen_count: int = 0,
    has_mx: Optional[bool] = None,
    whois_days_old: Optional[int] = None,
    fuzzer: Optional[str] = None,
    # Semnale de legitimitate
    spf_present: Optional[bool] = None,
    dkim_present: Optional[bool] = None,
    dmarc_present: Optional[bool] = None,
    dmarc_policy: Optional[str] = None,  # 'reject'|'quarantine'|'none'|None
    # opțional: dacă știi că domeniul e înregistrat (are A/AAAA/NS/MX)
    is_registered: Optional[bool] = None,
    # absorbim parametri suplimentari fără să dăm eroare
    **extras: Any,
) -> int:
    """Scor 0..100 pe bază de semnale normalizate și mitigări multiplicative.
    Lipsa semnalelor nu rupe funcția. Parametrii necunoscuți sunt ignorați.
    """
    # Componente normalizate [0..1]
    c_dns = 1.0 if dns_ok else 0.0
    c_http = _norm_http(http_status)
    c_sld = _norm_sld_similarity(sld_distance)
    c_tld = 1.0 if (tld and tld.lower() in HIGH_RISK_TLDS) else 0.0
    c_visual = 1.0 if ("-" in domain or any(ch.isdigit() for ch in domain)) else 0.0
    c_mx = 1.0 if has_mx else 0.0
    c_whois = _norm_whois_days(whois_days_old)
    c_ct = _norm_ct_seen(ct_seen_count)
    c_fuzzer = _norm_fuzzer(fuzzer)

    # Scor de bază (suma ponderată = 100)
    base = (
        WEIGHTS["dns_ok"] * c_dns
        + WEIGHTS["http"] * c_http
        + WEIGHTS["sld_similarity"] * c_sld
        + WEIGHTS["tld_risky"] * c_tld
        + WEIGHTS["visual"] * c_visual
        + WEIGHTS["mx"] * c_mx
        + WEIGHTS["whois_fresh"] * c_whois
        + WEIGHTS["ct_seen"] * c_ct
        + WEIGHTS["fuzzer"] * c_fuzzer
    )

    # factor de mitigare [0..1]
    factor = _mitigation_factor(
        spf_present=spf_present,
        dkim_present=dkim_present,
        dmarc_present=dmarc_present,
        dmarc_policy=dmarc_policy,
    )

    final = int(round(base * factor))
    return _cap(final)


def is_alert(score: int) -> bool:
    return score >= settings.scoring.alert_threshold


# ------------- compat wrapper (ca să nu-ți pice codul vechi) -------------

def compute_risk_score_legacy(domain: str, dns_ok: bool, http_status: int | None) -> int:
    return compute_risk_score(domain=domain, dns_ok=dns_ok, http_status=http_status)
