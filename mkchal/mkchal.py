#!/usr/bin/env -S uv run --script
#
# /// script
# requires-python = ">=3.12"
# dependencies = [
#    "jinja2>=3.1.6",
#    "msgspec>=0.21.1",
#    "rich>=15.0.0",
# ]
# ///
import argparse
import os
import re
import stat
import warnings
from enum import Enum
from pathlib import Path

import jinja2
import msgspec

ROOT_DOMAIN = os.getenv("ROOT_DOMAIN", "b01le.rs")
DOCKER_REGISTRY = "localhost:5000"

SRC = Path("src")
DEPLOY = Path("deploy")
DIST = Path("dist")
SOLVE = Path("solve")

CONTEXT = Path(__file__).resolve().parent.parent
SRC_DIR = CONTEXT / SRC
TEMPLATES_DIR = CONTEXT / "mkchal" / "templates"

TEMPLATE_ENV = jinja2.Environment(
    loader=jinja2.FileSystemLoader(TEMPLATES_DIR),
    undefined=jinja2.StrictUndefined,
    autoescape=False,
    keep_trailing_newline=True,
    trim_blocks=True,
    lstrip_blocks=True,
)


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


class Challenge(msgspec.Struct, kw_only=True, omit_defaults=True, frozen=True):
    """Challenge metadata written to ``chal.json``."""

    name: str
    author: str
    description: str
    flag: str
    difficulty: ChallengeDifficulty
    autodeploy: bool
    ports: list[int] = msgspec.field(default_factory=list)
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
        return msgspec.json.format(encoded, indent=4).decode() + "\n"


class GeneratedFile(msgspec.Struct, frozen=True):
    """A template and the directory where its rendered file belongs."""

    source: Path
    target_directory: Path
    executable: bool = False

    @property
    def destination(self) -> Path:
        return self.target_directory / self.source.name.removesuffix(".j2")


class ChallengeProject(msgspec.Struct, kw_only=True):
    """A challenge together with the options used to generate its project."""

    challenge: Challenge
    category: Category
    deploy: DeployType
    build: bool = False
    registry: str = DOCKER_REGISTRY
    domain: str = ROOT_DOMAIN

    @property
    def safe_name(self) -> str:
        return safe_name(self.challenge.name)

    @property
    def port(self) -> int:
        return self.challenge.ports[0] if self.challenge.ports else 1337

    @property
    def compiled(self) -> bool:
        return self.category in COMPILED_CHAL_TYPES

    @property
    def deployed(self) -> bool:
        return self.deploy != DeployType.NO_DEPLOY

    @property
    def image(self) -> str:
        return f"{self.registry}/{self.safe_name}"

    @property
    def template_family(self) -> str:
        if self.compiled:
            return "pwn"
        if self.category == Category.WEB:
            return "web"
        return ""

    def generation_manifest(self) -> list[GeneratedFile]:
        """Return the complete declarative file manifest for ``project``."""

        web = self.category == Category.WEB
        klodd = self.deploy == DeployType.KLODD
        source_template = (
            Path("pwn/sample.c.j2") if self.compiled else Path("web/sample.py.j2") if web else Path("sample.py.j2")
        )
        files = [
            GeneratedFile(Path("README.md.j2"), Path()),
            GeneratedFile(source_template, SRC),
        ]

        if self.deployed:
            template_dir = Path(self.template_family)
            files.extend(
                (
                    GeneratedFile(template_dir / "Dockerfile.j2", SRC),
                    GeneratedFile(Path("docker-compose.yml.j2"), SRC),
                    GeneratedFile(Path("dev.sh.j2"), Path(), executable=True),
                )
            )
        if self.build:
            files.extend(
                (
                    GeneratedFile(Path("pwn/host/build.sh.j2"), Path(), executable=True),
                    GeneratedFile(Path("pwn/build.sh.j2"), SRC, executable=True),
                    GeneratedFile(Path("pwn/build.Dockerfile.j2"), SRC),
                )
            )
        if klodd:
            template = Path("web/challenge.yml.j2") if web else Path("challenge.yml.j2")
            files.append(GeneratedFile(template, DEPLOY))
        if web and klodd:
            files.append(GeneratedFile(Path("web/klodd/run.sh.j2"), Path(), executable=True))
        return files

    def create(self):
        """Generate a challenge project from its declarative manifest."""

        destination = SRC_DIR / self.category.value / self.challenge.name
        destination.mkdir(parents=True, exist_ok=True)
        for directory in (SRC, DIST, SOLVE):
            (destination / directory).mkdir(parents=True, exist_ok=True)

        for generated_file in self.generation_manifest():
            output = destination / generated_file.destination
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(render_template(generated_file.source, self), encoding="utf-8")
            if generated_file.executable:
                make_file_executable(output)
        (destination / "chal.json").write_text(self.challenge.formatted(), encoding="utf-8")
        (destination / SRC / "flag.txt").write_text(self.challenge.flag, encoding="utf-8")

    def check_name_available(self, loaded_challenges: dict[str, dict[str, Challenge]]) -> None:
        """Check whether the challenge name is available in its category."""

        if not loaded_challenges:
            raise ValueError("No challs loaded")
        category = self.category.value
        for challenge_name in loaded_challenges[category]:
            if self.safe_name == safe_name(challenge_name):
                raise ValueError(
                    f"Name {self.challenge.name} conflicts with challenge {challenge_name} in category {category}"
                )


def make_file_executable(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def render_template(template: Path, project: ChallengeProject) -> str:
    return TEMPLATE_ENV.get_template(template.as_posix()).render(challenge=project.challenge, project=project)


def safe_name(name: str) -> str:
    """Create a name safe for paths and Docker resources."""

    return re.sub(r"^-+|-+$", "", re.sub(r"[^a-z0-9-]", "", re.sub(" ", "-", name.lower())))


def load_challenges() -> dict[str, dict[str, Challenge]]:
    """Decode existing metadata directly into ``Challenge`` objects."""

    challenges: dict[str, dict[str, Challenge]] = {category.value: {} for category in Category}
    for category_dir in SRC_DIR.iterdir():
        if not category_dir.is_dir() or category_dir.name not in challenges:
            continue
        for challenge_dir in category_dir.iterdir():
            challenge = msgspec.json.decode((challenge_dir / "chal.json").read_bytes(), type=Challenge)
            challenges[category_dir.name][challenge_dir.name] = challenge
    return challenges


def resolve_build_option(challenge_type: Category, deploy: DeployType, requested: bool) -> bool:
    """Validate ``--build`` for a category and return whether it is enabled."""

    enabled = requested and challenge_type in COMPILED_CHAL_TYPES and deploy != DeployType.NO_DEPLOY
    if requested and challenge_type not in COMPILED_CHAL_TYPES:
        warnings.warn(f"--build is not supported for {challenge_type.value} challenges; ignoring it.")
    elif requested and deploy == DeployType.NO_DEPLOY:
        warnings.warn("--build requires a deployment; ignoring it.")
    if challenge_type == Category.PWN and deploy != DeployType.NO_DEPLOY and not enabled:
        warnings.warn("pwn challenge generated without --build; provide src/chall before running it.")
    return enabled


def main() -> None:
    try:
        loaded_challenges = load_challenges()
    except (OSError, msgspec.DecodeError) as error:
        print(error)
        print("Error: Challenge repo is malformed")
        return

    parser = argparse.ArgumentParser(prog="mkchal", description="Creates a sample challenge for a ctf")
    parser.add_argument("--name", required=True, help="The name of the challenge.")
    parser.add_argument("--desc", default="example description", help="The description of the challenge.")
    parser.add_argument("--author", required=True, help="The author of the challenge.")
    parser.add_argument("--flag", default="bctf{fake_flag}", help="The challenge flag.")
    parser.add_argument(
        "--type",
        type=Category,
        required=True,
        choices=Category,
        help="The type of the challenge.",
    )
    parser.add_argument(
        "--deploy",
        type=DeployType,
        required=True,
        choices=DeployType,
        help="How the challenge will be deployed",
    )
    parser.add_argument("--ports", type=int, help="The ports that the challenge runs on inside the container.")
    parser.add_argument(
        "--autodeploy",
        default=True,
        action=argparse.BooleanOptionalAction,
        help="Whether or not the challenge can be automatically deployed.",
    )
    parser.add_argument(
        "--difficulty",
        type=ChallengeDifficulty,
        required=True,
        choices=ChallengeDifficulty,
        help="The challenge difficulty.",
    )
    parser.add_argument(
        "--build",
        action=argparse.BooleanOptionalAction,
        help="Generate the opt-in container build system for deployed pwn and rev challenges.",
    )
    args = parser.parse_args()

    build = resolve_build_option(args.type, args.deploy, args.build)
    ports = [args.ports] if args.ports else [1337] if args.deploy != DeployType.NO_DEPLOY else []

    challenge = Challenge(
        name=safe_name(args.name),
        author=args.author,
        description=args.desc,
        flag=args.flag,
        difficulty=args.difficulty,
        autodeploy=args.autodeploy,
        ports=ports,
    )
    project = ChallengeProject(
        challenge=challenge,
        category=args.type,
        deploy=args.deploy,
        build=build,
    )

    project.check_name_available(loaded_challenges)

    project.create()

    print(f"Done. Run `git switch -c {challenge.name}_{challenge.author}` to switch to a branch and start working.")


if __name__ == "__main__":
    main()
