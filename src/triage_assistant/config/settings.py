"""
Settings — typed configuration loaded from environment variables.

Uses pydantic-settings so every config value is validated at startup.
If something's missing or the wrong type, the app fails fast with a
clear message — not at 3 AM during a triage run.
"""
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Wazuh Indexer
    wazuh_indexer_host: str = "192.168.1.7"
    wazuh_indexer_port: int = 9200
    wazuh_indexer_user: str = "admin"
    wazuh_indexer_password: str
    wazuh_verify_tls: bool = False

    # Ollama
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"
    ollama_temperature: float = 0.1

    # NVD (optional)
    nvd_api_key: str | None = None

    # MITRE
    mitre_attack_json_path: str = "data/mitre/enterprise-attack.json"

    # Logging
    log_level: str = "INFO"
    
def get_settings() -> Settings:
    """Single function used everywhere to access settings."""
    return Settings()