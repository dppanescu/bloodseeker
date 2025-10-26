from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional, List

class SeedCreate(BaseModel):
    name: str = Field(min_length=3, max_length=255)

class Seed(BaseModel):
    id: int
    name: str
    class Config:
        from_attributes = True

class Variant(BaseModel):
    id: int
    domain: str
    status: str
    risk_score: int
    class Config:
        from_attributes = True
