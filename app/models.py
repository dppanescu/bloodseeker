from __future__ import annotations
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import (
    String, Column, Integer, ForeignKey, DateTime, Boolean, Float, Text, JSON, func,
    event, and_, or_,
)
from .db import Base

class SeedDomain(Base):
    __tablename__ = 'seed_domains'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    deleted_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    variants: Mapped[list['Variant']] = relationship('Variant', back_populates='seed', cascade='all, delete-orphan', passive_deletes=True)
    ct_candidates: Mapped[list['CTCandidate']] = relationship('CTCandidate', cascade='all, delete-orphan', passive_deletes=True)
    options: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    generator: Mapped[str] = mapped_column(String(16), nullable=False, default="simple", server_default="simple")

class Variant(Base):
    __tablename__ = 'variants'
    fuzzer         = Column(String(64), nullable=True)
    is_registered  = Column(Boolean,   nullable=True)
    has_mx         = Column(Boolean,   nullable=True)
    mx_count       = Column(Integer,   nullable=True)

    banner_http    = Column(Text,      nullable=True)
    banner_smtp    = Column(Text,      nullable=True)

    lsh_algo       = Column(String(16), nullable=True)
    lsh_distance   = Column(Float,      nullable=True)
    phash_distance = Column(Float,      nullable=True)

    screenshot_path = Column(Text,     nullable=True)
    id: Mapped[int] = mapped_column(primary_key=True)
    seed_id: Mapped[int] = mapped_column(ForeignKey('seed_domains.id', ondelete='CASCADE'), index=True)
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default='new', server_default='new')
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default='0')
    first_seen_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_checked_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True))

    seed: Mapped['SeedDomain'] = relationship('SeedDomain', back_populates='variants')
    check_runs: Mapped[list['CheckRun']] = relationship('CheckRun', cascade='all, delete-orphan', passive_deletes=True)

class CheckRun(Base):
    __tablename__ = 'check_runs'
    id: Mapped[int] = mapped_column(primary_key=True)
    variant_id: Mapped[int] = mapped_column(ForeignKey('variants.id', ondelete='CASCADE'), index=True)
    ts: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    dns_ok: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default='false')
    http_status: Mapped[int | None] = mapped_column(Integer)
    notes: Mapped[JSON | None] = mapped_column(JSON)

class CTCandidate(Base):
    __tablename__ = 'ct_candidates'
    id: Mapped[int] = mapped_column(primary_key=True)
    seed_id: Mapped[int] = mapped_column(ForeignKey('seed_domains.id', ondelete='CASCADE'))
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default='certstream', server_default='certstream')
    first_seen: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    seen_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default='1')

class Alert(Base):
    __tablename__ = 'alerts'
    id: Mapped[int] = mapped_column(primary_key=True)
    seed_id: Mapped[int | None] = mapped_column(ForeignKey('seed_domains.id', ondelete='SET NULL'), nullable=True)
    variant_id: Mapped[int | None] = mapped_column(ForeignKey('variants.id', ondelete='SET NULL'), nullable=True)
    level: Mapped[str] = mapped_column(String(16), nullable=False)
    channel: Mapped[str] = mapped_column(String(16), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class WhoisCache(Base):
    __tablename__ = "whois_cache"
    variant_id: Mapped[int] = mapped_column(ForeignKey('variants.id', ondelete='CASCADE'), primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    data: Mapped[JSON] = mapped_column(JSON, nullable=False)  # JSON normalizat (și suficient pentru UI)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="whoisxmlapi", server_default="whoisxmlapi")
    fetched_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

# -------------------------
# Event listener „recomandat”
# -------------------------
@event.listens_for(CheckRun, "after_insert")
def checkrun_after_insert(mapper, connection, target):
    """
    La primul CheckRun pentru o variantă:
      - dacă statusul e NULL sau 'new' și NU e 'stop', devine 'monitoring'.
      - dacă e 'stop', nu schimbăm nimic.
    Funcționează în orice proces care importă acest modul.
    """
    variants = Variant.__table__
    connection.execute(
        variants.update()
        .where(
            and_(
                variants.c.id == target.variant_id,
                variants.c.status != 'stop',
                or_(variants.c.status.is_(None), variants.c.status == 'new'),
            )
        )
        .values(status='monitoring')
    )
