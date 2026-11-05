"""
RedOps Configuration Module
Manages application settings, safety allowlists, LLM configurations, and database paths.
"""
import os
import ipaddress
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Flask Core
    SECRET_KEY = os.getenv("SECRET_KEY", "redops-master-secret-key-cyber-2026")
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    DEBUG = os.getenv("FLASK_DEBUG", "1").lower() in ("1", "true", "yes")

    # Network & Server
    HOST = os.getenv("HOST", "127.0.0.1")
    PORT = int(os.getenv("PORT", "5000"))

    # Database
    DATABASE_PATH = os.path.join(BASE_DIR, os.getenv("DATABASE_PATH", "database/redops.db"))
    
    # Reports Directory
    REPORTS_DIR = os.path.join(BASE_DIR, "reports")

    # Safety & Allowlist Policies
    ENFORCE_STRICT_ALLOWLIST = os.getenv("ENFORCE_STRICT_ALLOWLIST", "true").lower() in ("1", "true", "yes")
    AUTHORIZED_TARGETS_RAW = os.getenv(
        "AUTHORIZED_TARGETS",
        "127.0.0.1,172.28.0.0/16,192.168.1.0/24,10.0.0.0/24,localhost"
    )

    # NVD API
    NVD_API_KEY = os.getenv("NVD_API_KEY", "")
    NVD_CACHE_TTL_HOURS = int(os.getenv("NVD_CACHE_TTL_HOURS", "24"))

    # AI Reasoning
    AI_PROVIDER = os.getenv("AI_PROVIDER", "local")  # local, openai, gemini, anthropic
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
    LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini")

    @classmethod
    def get_allowed_targets(cls):
        """Returns clean list of authorized target strings."""
        return [t.strip() for t in cls.AUTHORIZED_TARGETS_RAW.split(",") if t.strip()]

    @classmethod
    def is_target_authorized(cls, target: str) -> bool:
        """
        Validates whether an IP address or hostname is strictly allowlisted.
        Blocks arbitrary Internet IP addresses and third-party systems.
        """
        if not cls.ENFORCE_STRICT_ALLOWLIST:
            return True

        if not target:
            return False

        target = target.strip().lower()
        if target in ("localhost", "127.0.0.1", "::1"):
            return True

        try:
            target_ip = ipaddress.ip_address(target)
            # Never permit scanning public Internet IPs without explicit lab config
            # Check against configured subnets / IPs
            for allowed in cls.get_allowed_targets():
                try:
                    if "/" in allowed:
                        network = ipaddress.ip_network(allowed, strict=False)
                        if target_ip in network:
                            return True
                    else:
                        if target_ip == ipaddress.ip_address(allowed):
                            return True
                except ValueError:
                    if allowed.lower() == target:
                        return True
            return False
        except ValueError:
            # Hostname check
            for allowed in cls.get_allowed_targets():
                if allowed.lower() == target:
                    return True
            return False
