import re
from enum import Enum
from pathlib import Path

import msgspec

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class Category(Enum):
    """Describes a CTF categorye."""

    REV = "rev"
    PWN = "pwn"
    CRYPTO = "crypto"
    WEB = "web"
    MISC = "misc"
    BLOCKCHAIN = "blockchain"
    OSINT = "osint"
    JAIL = "jail"


COMPILED_CHAL_TYPES = (Category.PWN, Category.REV)


class ChallengeDifficulty(Enum):
    """Describes a CTF challenge difficulty."""

    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    IMPOSSIBLE = "impossible"


class DeployType(Enum):
    """Describes a deployment type."""

    DOCKER_COMPOSE = "docker"
    KLODD = "klodd"
    NO_DEPLOY = "none"


class ComposeConfig(msgspec.Struct, forbid_unknown_fields=True):
    services: list[str]
    file: str = "src/docker-compose.yml"

    def __post_init__(self) -> None:
        if not self.file:
            raise ValueError("distribution.compose.file cannot be empty")
        if not self.services or not all(self.services):
            raise ValueError("distribution.compose.services must contain non-empty strings")
        if len(self.services) != len(set(self.services)):
            raise ValueError("distribution.compose.services contains duplicates")


class DistConfig(msgspec.Struct, forbid_unknown_fields=True):
    files: list[str]
    compose: ComposeConfig | None = None

    def __post_init__(self) -> None:
        if not self.files or not all(self.files):
            raise ValueError("distribution.files must contain non-empty strings")


class Challenge(msgspec.Struct, kw_only=True, omit_defaults=True, frozen=True):
    """Challenge metadata written to ``chal.json``."""

    name: str
    author: str
    description: str
    flag: str
    difficulty: ChallengeDifficulty
    autodeploy: bool
    ports: list[int] = msgspec.field(default_factory=list)
    distribution: DistConfig | None = None
    hidden: bool | None = None
    minPoints: int | None = None
    maxPoints: int | None = None
    tiebreakEligible: bool | None = None
    prereqs: list[str] | None = None
    tags: list[str] | None = None

    def __post_init__(self) -> None:
        if re.fullmatch(r"bctf\{[^}]*\}", self.flag) is None:
            raise ValueError(r"Flag does not match bctf\{[^}]*\}")

    def formatted(self) -> str:
        encoded = msgspec.json.encode(self)
        return str(msgspec.json.format(encoded, indent=4).decode()) + "\n"
