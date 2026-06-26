"""
Configuration module for LLM Gateway.
Manages the different security layers (D0, DA, DB, DC-*, DT) and their settings.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional, List
import os
import logging

_logger = logging.getLogger(__name__)

# pydantic-settings resolves env_file relative to the process CWD, so we resolve
# the same way to report exactly which .env (if any) backed this config.
ENV_FILE_PATH = os.path.abspath(".env")
ENV_FILE_FOUND = os.path.isfile(ENV_FILE_PATH)

class Settings(BaseSettings):
    # Security Layer Configuration.
    # Defaults are fail-safe (OFF): a missing/unreadable .env must NOT silently
    # enforce or claim defenses. set_layer.sh always writes all 7 flags, so the
    # experiment sweep is unaffected; these defaults only govern the no-config
    # case, where reporting an empty active set (caught by the harness /layers
    # assertion) is far safer than faking a full defense-in-depth profile.
    layer_d0: bool = False  # No defenses (baseline label)
    layer_da: bool = False  # Defense A (System Prompt)
    layer_db: bool = False  # Defense B (Input Guardrail)
    layer_dc_a: bool = False  # DC-a: Role-based grants
    layer_dc_b: bool = False  # DC-b: Row Level Security
    layer_dc_c: bool = False  # DC-c: Column masking
    layer_dt: bool = False  # DT: Restricted tool interface
    
    # Feature Flags
    enable_trace_id: bool = True
    enable_latency_logging: bool = True
    enable_identity_propagation: bool = True
    
    # Database Settings
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "marketplace"
    db_user: str = "role_app"
    db_password: str = "change_me"
    
    # LLM Settings
    llm_endpoint: str = "http://localhost:8001/v1/completions"
    llm_temperature: float = 0.0  # For deterministic responses
    
    # Logging Settings
    log_level: str = "INFO"
    
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

# Global configuration instance
config = Settings()

if not ENV_FILE_FOUND:
    _logger.warning(
        "No .env found at %s — all defense-layer flags default to OFF (baseline). "
        "If you intended a defense profile, run set_layer.sh and (re)start the "
        "gateway from the repo root so the flags load.",
        ENV_FILE_PATH,
    )

def env_provenance() -> dict:
    """Where this config was loaded from, for startup provenance logging."""
    return {"env_file": ENV_FILE_PATH, "env_file_found": ENV_FILE_FOUND}

def get_config():
    """
    Get the global configuration instance
    """
    return config

def get_active_layers() -> List[str]:
    """
    Get list of active security layers
    """
    active_layers = []
    if config.layer_d0:
        active_layers.append("D0")
    if config.layer_da:
        active_layers.append("DA")  
    if config.layer_db:
        active_layers.append("DB")
    if config.layer_dc_a:
        active_layers.append("DC-a")
    if config.layer_dc_b:
        active_layers.append("DC-b")
    if config.layer_dc_c:
        active_layers.append("DC-c")
    if config.layer_dt:
        active_layers.append("DT")
    
    return active_layers

def is_layer_enabled(layer: str) -> bool:
    """
    Check if a specific layer is enabled
    """
    layer_map = {
        "D0": config.layer_d0,
        "DA": config.layer_da,
        "DB": config.layer_db,
        "DC-a": config.layer_dc_a,
        "DC-b": config.layer_dc_b,
        "DC-c": config.layer_dc_c,
        "DT": config.layer_dt
    }
    
    return layer_map.get(layer, False)