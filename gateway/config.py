"""
Configuration module for LLM Gateway.
Manages the different security layers (D0, DA, DB, DC-*, DT) and their settings.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional, List

class Settings(BaseSettings):
    # Security Layer Configuration
    layer_d0: bool = True  # No defenses
    layer_da: bool = True  # Defense A (System Prompt)
    layer_db: bool = True  # Defense B (Input Guardrail)
    layer_dc_a: bool = True  # DC-a: Role-based grants
    layer_dc_b: bool = True  # DC-b: Row Level Security
    layer_dc_c: bool = True  # DC-c: Column masking
    layer_dt: bool = True  # DT: Restricted tool interface
    
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