from dataclasses import dataclass, field
import os
from pathlib import Path


@dataclass(frozen=True)
class SpiderFootConfig:
    shodan_api_key: str = field(default_factory=lambda: os.getenv("SPIDERFOOT_SHODAN_API_KEY", ""))
    virustotal_api_key: str = field(default_factory=lambda: os.getenv("SPIDERFOOT_VT_API_KEY", ""))
    hunter_api_key: str = field(default_factory=lambda: os.getenv("SPIDERFOOT_HUNTER_API_KEY", ""))


@dataclass(frozen=True)
class TheHarvesterConfig:
    keys_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("THEHARVESTER_API_KEYS_PATH", "config/theharvester_keys.yaml")
        )
    )


@dataclass(frozen=True)
class AmassConfig:
    datasources_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("AMASS_CONFIG_PATH", "config/amass_datasources.yaml")
        )
    )


@dataclass(frozen=True)
class BBOTConfig:
    secrets_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("BBOT_SECRETS_FILE", Path.home() / ".bbot" / "secrets.yml")
        ).expanduser()
    )


@dataclass(frozen=True)
class NotificationConfig:
    telegram_bot_token: str = field(default_factory=lambda: os.getenv("TELEGRAM_BOT_TOKEN", ""))
    telegram_chat_id: str = field(default_factory=lambda: os.getenv("TELEGRAM_CHAT_ID", ""))


class AppConfig:
    def __init__(self):
        self.spiderfoot = SpiderFootConfig()
        self.theharvester = TheHarvesterConfig()
        self.amass = AmassConfig()
        self.bbot = BBOTConfig()
        self.notifications = NotificationConfig()


def get_config() -> AppConfig:
    return AppConfig()
