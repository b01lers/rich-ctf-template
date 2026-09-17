from __future__ import annotations

import argparse
import os
import stat
import warnings
from enum import Enum
from json import dumps, loads
from pathlib import Path
from re import match, sub

# Infra constants
ROOT_DOMAIN = os.getenv("ROOT_DOMAIN", "b01le.rs")  # TODO: make it compliant with the testing workflow and VPS
HTTP_ENTRY = 443
TCP_SEC_ENTRY = 1337
DOCKER_REGISTRY = "localhost:5000"

# Default challenge directories
SRC = "src"
DEPLOY = "deploy"
DIST = "dist"
SOLVE = "solve"


# Default challenge filenames
CHAL_JSON = "chal.json"
DOCKERFILE = "Dockerfile"
COMPOSE = "docker-compose.yml"
SAMPLE_PY = "sample.py"
SAMPLE_C = "sample.c"
KLODD_YAML = "challenge.yml"
BUILD_SH = "build.sh"
HOST_BUILD_TEMPLATE = "host_build.sh"
DOCKERFILE_BUILD = "Dockerfile_build"
DEV_SH = "dev.sh"
RUN_SH = "run.sh"
README = "README.md"
FLAG = "flag.txt"

# the current path this script is running in
CONTEXT = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# where the challenge category and folders will go
SRC_DIR = CONTEXT / "src"

# location of the templates directory
TEMPLATES_DIR = CONTEXT / "mkchal" / "templates"

# location of the pwn template directory
PWN_TEMPLATE_DIR = TEMPLATES_DIR / "pwn"

"""
Should be in the structure of
type1: [chal.json1, chal.json2...],
type2: [...],
...
"""
loaded_challs = {}
DEBUG = False


class ChallengeType(str, Enum):
    """Describes a CTF challenge type."""

    REV = "rev"
    PWN = "pwn"
    CRYPTO = "crypto"
    WEB = "web"
    MISC = "misc"
    BLOCKCHAIN = "blockchain"
    OSINT = "osint"
    JAIL = "jail"


class ChallengeDifficulty(str, Enum):
    """Describes a CTF challenge difficulty"""

    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    IMPOSSIBLE = "impossible"


class DeployType(str, Enum):
    """Describes a deployment type."""

    DOCKER_COMPOSE = "docker"
    KLODD = "klodd"
    NO_DEPLOY = "none"


COMPILED_CHAL_TYPES = (ChallengeType.PWN, ChallengeType.REV)


def make_file_executable(path: Path):
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def resolve_build_option(challenge_type: ChallengeType, deploy: DeployType, requested: bool) -> bool:
    """Validate --build for a category and return whether it is enabled."""
    enabled = requested and challenge_type in COMPILED_CHAL_TYPES and deploy != DeployType.NO_DEPLOY
    if requested and challenge_type not in COMPILED_CHAL_TYPES:
        warnings.warn(f"--build is not supported for {challenge_type.value} challenges; ignoring it.")
    elif requested and deploy == DeployType.NO_DEPLOY:
        warnings.warn("--build requires a deployment; ignoring it.")
    if challenge_type == ChallengeType.PWN and deploy != DeployType.NO_DEPLOY and not enabled:
        warnings.warn("pwn challenge generated without --build; provide src/chall before running it.")
    return enabled


class ChallengeUtils:
    @staticmethod
    def validate_name(challenge: Challenge) -> tuple[bool, str]:
        """Validates a challenge name"""

        if len(loaded_challs.keys()) < 1:
            return (False, "Unloaded challs")
        for chall_name in loaded_challs[challenge.type.value].keys():
            if ChallengeUtils.safe_name(challenge.name) == ChallengeUtils.safe_name(chall_name):
                return (
                    False,
                    f"Name {challenge.name} conficts with challenge {chall_name} in category {challenge.type.value}",
                )
        return True, "success"

    @staticmethod
    def validate_flag(flag: str) -> bool:
        """Validates whether a flag fits the required format"""

        return match(r"^bctf\{.*\}$", flag) is not None

    @staticmethod
    def generate(challenge_obj: Challenge) -> bool:
        """Generates a challenge. Assumes valid fields"""
        challenge: Path = SRC_DIR / challenge_obj.type.value / challenge_obj.name
        challenge.mkdir(parents=True, exist_ok=DEBUG)
        ChallengeUtils.__generate_defaults(challenge_obj, challenge)
        ChallengeUtils.__generate_sources(challenge_obj, challenge)
        ChallengeUtils.__generate_deployments(challenge_obj, challenge)
        return True

    @staticmethod
    def retrieve_valid_port(type: ChallengeType) -> tuple[bool, int]:
        """returns: (success, port)"""
        # TODO create server on b01lers server that generates a valid port
        # We let the user choose a port for now, with traefik this shouldn't be needed
        return False, 0

    @staticmethod
    def load_challenges() -> dict:
        """
        Loads all currently created challenges into a dict.
        Assumes proper directory structure.
        """

        d: dict = {
            "rev": {},
            "pwn": {},
            "crypto": {},
            "blockchain": {},
            "web": {},
            "misc": {},
            "osint": {},
            "jail": {},
        }
        for dir in SRC_DIR.iterdir():
            if dir.is_dir() and dir.name in d.keys():
                for challenge in dir.iterdir():
                    d[dir.name][challenge.name] = loads((challenge / CHAL_JSON).read_text())
        return d

    @staticmethod
    def generate_service_name(name: str) -> str:
        """Ensures uniqueness between challenge service names"""
        return f"{name}"

    @staticmethod
    def generate_file_content(filename: Path, kwargs: dict) -> str:
        """generates the sample file content for a template file"""

        return filename.read_text().format(**kwargs)

    @staticmethod
    def safe_name(name: str) -> str:
        """Creates a safe name for docker services"""

        return sub(r"^-+|-+$", "", sub(r"[^a-z0-9-]", "", sub(" ", "-", name.lower())))

    @staticmethod
    def __generate_defaults(challenge_obj: Challenge, challenge: Path) -> None:
        (challenge / SRC).mkdir(parents=True, exist_ok=DEBUG)
        (challenge / DIST).mkdir(parents=True, exist_ok=DEBUG)
        (challenge / SOLVE).mkdir(parents=True, exist_ok=DEBUG)
        (challenge / README).write_text(challenge_obj.gen_readme(), encoding="utf-8")
        (challenge / CHAL_JSON).write_text(str(challenge_obj), encoding="utf-8")
        (challenge / SRC / FLAG).write_text(challenge_obj.flag, encoding="utf-8")

    @staticmethod
    def __generate_sources(challenge_obj: Challenge, challenge: Path) -> None:
        if challenge_obj.type in COMPILED_CHAL_TYPES:
            (challenge / SRC / SAMPLE_C).write_text(challenge_obj.gen_sample(), encoding="utf-8")
        else:
            (challenge / SRC / SAMPLE_PY).write_text(challenge_obj.gen_sample(), encoding="utf-8")

        if challenge_obj.build:
            (challenge / BUILD_SH).write_text(challenge_obj.gen_build_script(), encoding="utf-8")
            make_file_executable(challenge / BUILD_SH)
            (challenge / SRC / BUILD_SH).write_text(
                challenge_obj.gen_source_build_script(),
                encoding="utf-8",
            )
            make_file_executable(challenge / SRC / BUILD_SH)
            (challenge / SRC / DOCKERFILE_BUILD).write_text(
                challenge_obj.gen_dockerfile_build(),
                encoding="utf-8",
            )

    @staticmethod
    def __generate_deployments(challenge_obj: Challenge, challenge: Path) -> None:
        if challenge_obj.deploy == DeployType.NO_DEPLOY:
            return

        (challenge / SRC / DOCKERFILE).write_text(challenge_obj.gen_dockerfile(), encoding="utf-8")
        (challenge / SRC / COMPOSE).write_text(challenge_obj.gen_docker_compose(), encoding="utf-8")

        (challenge / DEV_SH).write_text(challenge_obj.gen_dev_sh(), encoding="utf-8")
        make_file_executable(challenge / DEV_SH)

        if challenge_obj.deploy == DeployType.KLODD:
            (challenge / DEPLOY).mkdir(parents=True, exist_ok=DEBUG)
            # TODO: b01lers kube interface would be different, wait for vinh's decision
            (challenge / DEPLOY / KLODD_YAML).write_text(
                challenge_obj.gen_klodd_challenge(),
                encoding="utf-8",
            )
            if challenge_obj.type == ChallengeType.WEB:
                (challenge / RUN_SH).write_text(challenge_obj.gen_run_sh(), encoding="utf-8")
                make_file_executable(challenge / RUN_SH)


class Challenge:
    """Represents a challenge object"""

    __slots__ = [
        "name",
        "author",
        "description",
        "flag",
        "type",
        "deploy",
        "ports",
        "hidden",
        "minPoints",
        "maxPoints",
        "tiebreakEligible",
        "prereqs",
        "tags",
        "difficulty",
        "auto",
        "build",
        "registry",
        "root_domain",
    ]
    optional_fields = [
        "ports",
        "hidden",
        "minPoints",
        "maxPoints",
        "tiebreakEligible",
        "prereqs",
        "tags",
    ]

    def __init__(
        self,
        name: str,
        author: str,
        description: str,
        flag: str,
        type: ChallengeType,
        deploy: DeployType,
        difficulty: ChallengeDifficulty,
        auto: bool = False,
        build: bool = False,
    ) -> None:
        self.name = name
        self.author = author
        self.description = description
        self.flag = flag
        self.type = type
        self.deploy = deploy
        self.ports = []
        self.auto = auto
        self.build = build and type in COMPILED_CHAL_TYPES and deploy != DeployType.NO_DEPLOY
        self.hidden = None
        self.minPoints = None
        self.maxPoints = None
        self.tiebreakEligible = None
        self.prereqs = None
        self.tags = None
        self.difficulty = difficulty
        self.registry = DOCKER_REGISTRY
        self.root_domain = ROOT_DOMAIN

    def to_json(self) -> dict:
        """converts a challenge to its valid chal.json output"""
        d: dict = {
            "name": self.name,
            "author": self.author,
            "description": self.description,
            "flag": self.flag,
            "difficulty": self.difficulty.value,
            "can_be_auto_deployed": self.auto,
        }
        for field in self.optional_fields:
            val = getattr(self, field)
            if isinstance(val, list) and len(val) > 0 or val is not None and not isinstance(val, list):
                d[field] = val
        return d

    def gen_readme(self) -> str:
        """Generates a README.md with instructions on how to setup the directory"""

        ret = f"""# __{self.name}__ by __{self.author}__ \
        \n## Directory Structure \
        \n``` \
        \n{self.name} \
        """
        if self.deploy == DeployType.KLODD:
            ret += """\n ├── deploy \
            \n │    └── Klodd deployment files \
            """
        ret += """\n ├── dist \
        \n │    └── files to be given to competitors \
        \n ├── solve \
        \n │    └── writeup and solution scripts \
        \n ├── src \
        \n │    └── challenge source and container files \
        \n ├── chall.json ── challenge information \
        \n ├── README.md ── this file \
        """
        if self.build:
            ret += """\n ├── build.sh ── builds src/chall"""
        if self.deploy != DeployType.NO_DEPLOY:
            ret += """\n └── dev.sh ── what you should use to test your challenge"""
        ret += """\n```"""
        ret += f"""\n## Quickstart to challenge development
Make sure you develop your challenge on a new branch. You can create one with
```bash
git switch -c {self.name}_{self.author}
```"""

        if self.deploy != DeployType.NO_DEPLOY:
            ret += f"""\n

This setup is well-suited for pwn, reverse engineering, non instanced web challenges, and cryptography challenges requiring a hosted service.

Delete the sample challenge before you start working.

If your challenge allows Remote Code Execution (RCE), it must be sandboxed using either:
 - [nsjail](https://github.com/google/nsjail)
 - [redpwn jail](https://github.com/redpwn/jail).
"""

        if self.build:
            ret += """\n### Build system (for pwn/rev challenges)
The generated build system compiles your executable in a Docker container and places it at `src/chall`.
The runtime `Dockerfile` uses this same executable when you test the challenge.

 - `./build.sh` explicitly builds the challenge.
 - `src/build.sh` contains the compilation steps run inside the builder image.
 - Normal `docker compose up --build` only uses an existing `src/chall`; it does not run the builder.
"""
            ret += " - `./dev.sh` runs the build script before starting the challenge.\n\n"
        elif self.type in COMPILED_CHAL_TYPES and self.deploy != DeployType.NO_DEPLOY:
            ret += """\n### Challenge executable
This challenge was generated without `--build`. Add an executable at `src/chall` before building the runtime container.

"""

        if self.deploy == DeployType.KLODD:
            ret += f"""\n### {self.name}/deploy
The sample deploy folder contains
- `challenge.yml`: Configuration file defining Klodd deployment settings.
If you're new to Klodd, avoid modifying these files without checking with the CTF developers.
"""

        ret += f"""\n### {self.name}/dist
Contains files distributed to competitors. If multiple files are included, bundle them into a ZIP archive.
### {self.name}/solve
Contains the challenge's writeup and solution scripts. A well-documented writeup is crucial for assessing challenge quality.
### {self.name}/src
Contains the challenge source files.
"""
        if self.deploy != DeployType.NO_DEPLOY:
            ret += f"""
If deployment is required, the `src` folder contains
 - `Dockerfile`: A basic setup for the challenge, accessible at port 1337.
 - `docker-compose.yml`: Defines deployment steps for the challenge.

Run the challenge directly from this directory with:
```bash
docker compose up --build
```

            ### {self.name}/dev.sh
**IMPORTANT**: Ensure the challenge can be fully deployed by running:
```bash
./dev.sh
```
"""
        ret += """## Merging
Once your challenge is complete, submit a **Pull Request (PR)**. The PR will be merged after a quality review on GitHub.
---
This README was autogenerated by `mkchal.py`, but written by Neil (CygnusX). Suggestions are welcome.
"""
        return ret

    def port(self) -> int:
        """Return the configured container port or the template default."""
        return self.ports[0] if self.ports else 1337

    def gen_dockerfile(self) -> str:
        """Generates a sample Dockerfile"""

        kwargs = {"name": ChallengeUtils.safe_name(self.name), "port": self.port()}
        if self.type in COMPILED_CHAL_TYPES:
            return ChallengeUtils.generate_file_content(PWN_TEMPLATE_DIR / DOCKERFILE, kwargs)
        if self.type == ChallengeType.WEB:
            return ChallengeUtils.generate_file_content(TEMPLATES_DIR / self.type.value / DOCKERFILE, kwargs)
        return ChallengeUtils.generate_file_content(TEMPLATES_DIR / DOCKERFILE, kwargs)

    def gen_docker_compose(self) -> str:
        """Generates a sample docker-compose.yml"""
        safe_name = ChallengeUtils.safe_name(self.name)
        kwargs = {
            "name": safe_name,
            "hash": ChallengeUtils.generate_service_name(safe_name),
            "port": self.port(),
            "privileged": (
                "        privileged: true # needed for redpwn jail to work\n"
                if self.type in COMPILED_CHAL_TYPES
                else ""
            ),
            "build_services": self.gen_compose_build_services(),
        }
        return ChallengeUtils.generate_file_content(TEMPLATES_DIR / COMPOSE, kwargs)

    def gen_compose_build_services(self) -> str:
        if not self.build:
            return ""

        safe_name = ChallengeUtils.safe_name(self.name)
        kwargs = {"hash": ChallengeUtils.generate_service_name(safe_name)}
        return ChallengeUtils.generate_file_content(PWN_TEMPLATE_DIR / "compose-build-services.yml", kwargs)

    def gen_sample(self) -> str:
        """Generates the sample challenge file"""

        kwargs = {"name": self.name, "port": self.port()}
        if self.type == ChallengeType.WEB:
            return ChallengeUtils.generate_file_content(
                TEMPLATES_DIR / self.type.value / SAMPLE_PY,
                kwargs,
            )
        if self.type in COMPILED_CHAL_TYPES:
            return ChallengeUtils.generate_file_content(PWN_TEMPLATE_DIR / SAMPLE_C, kwargs)
        return ChallengeUtils.generate_file_content(TEMPLATES_DIR / SAMPLE_PY, kwargs)

    def gen_klodd_challenge(self) -> str:
        """Generates a sample challenge.yml"""
        safe_name = ChallengeUtils.safe_name(self.name)
        kwargs = {
            "unsafe_name": self.name,
            "name": safe_name,
            "port": self.port(),
            "image": f"{self.registry}/{safe_name}",
        }
        if self.type == ChallengeType.WEB:
            return ChallengeUtils.generate_file_content(TEMPLATES_DIR / self.type.value / KLODD_YAML, kwargs)
        return ChallengeUtils.generate_file_content(TEMPLATES_DIR / KLODD_YAML, kwargs)

    def gen_build_script(self) -> str:
        """Generates the host-side build script for compiled challenges."""
        assert self.build
        return ChallengeUtils.generate_file_content(PWN_TEMPLATE_DIR / HOST_BUILD_TEMPLATE, {})

    def gen_source_build_script(self) -> str:
        """Generates the build script executed inside the builder image."""
        assert self.build
        return ChallengeUtils.generate_file_content(PWN_TEMPLATE_DIR / BUILD_SH, {})

    def gen_dockerfile_build(self) -> str:
        """Generates Dockerfile_build for compiled challenges."""
        assert self.build
        return ChallengeUtils.generate_file_content(PWN_TEMPLATE_DIR / DOCKERFILE_BUILD, {})

    def gen_run_sh(self):
        assert self.type == ChallengeType.WEB and self.deploy == DeployType.KLODD

        safe_name = ChallengeUtils.safe_name(self.name)
        kwargs = {
            "name": safe_name,
            "registry": self.registry,
        }

        return ChallengeUtils.generate_file_content(TEMPLATES_DIR / self.type.value / "klodd" / RUN_SH, kwargs)

    def gen_dev_sh(self):
        safe_name = ChallengeUtils.safe_name(self.name)
        kwargs = {
            "name": safe_name,
            "local_command": (
                "curl http://localhost:1337" if self.type == ChallengeType.WEB else "ncat localhost 1337"
            ),
        }
        return ChallengeUtils.generate_file_content(TEMPLATES_DIR / DEV_SH, kwargs)

    def create(self) -> bool:
        """Creates the challenge structure for a challenge"""
        return ChallengeUtils.generate(self)

    def __repr__(self) -> str:
        return dumps(self.to_json(), indent=4)


if __name__ == "__main__":
    print()
    try:
        loaded_challs = ChallengeUtils.load_challenges()
    except Exception as e:
        print(e)
        print("Error: " + "Challenge repo is malformed")
        exit()
    parser = argparse.ArgumentParser(prog="mkchal", description="Creates a sample challenge for a ctf")

    parser.add_argument("--name", type=str, required=True, help="The name of the challenge.")

    parser.add_argument(
        "--desc", type=str, required=False, help="The description of the challenge.", default="example description"
    )

    parser.add_argument("--author", type=str, required=True, help="The author of the challenge.")

    parser.add_argument("--flag", type=str, required=False, help="The challenge flag.", default="bctf{fake_flag}")

    parser.add_argument(
        "--type",
        type=ChallengeType,
        required=True,
        choices=[c.value for c in ChallengeType],
        help="The type of the challenge.",
    )

    parser.add_argument(
        "--deploy",
        type=DeployType,
        required=True,
        choices=[c.value for c in DeployType],
        help="How the challenge will be deployed",
    )

    parser.add_argument(
        "--ports",
        type=int,
        required=False,
        help="The ports that the challenge runs on inside the container.",
    )

    parser.add_argument(
        "--autodeploy",
        type=bool,
        required=True,
        choices=[False, True].copy(),
        help="Whether or not the challenge can be automatically deployed.",
    )

    parser.add_argument(
        "--difficulty",
        type=ChallengeDifficulty,
        required=True,
        choices=[c.value for c in ChallengeDifficulty],
        help="The challenge difficulty.",
    )

    parser.add_argument(
        "--build",
        action="store_true",
        help="Generate the opt-in container build system for deployed pwn and rev challenges.",
    )

    args = parser.parse_args()

    build_enabled = resolve_build_option(args.type, args.deploy, args.build)

    c = Challenge(
        ChallengeUtils.safe_name(args.name),
        args.author,
        args.desc,
        args.flag,
        args.type,
        args.deploy,
        args.difficulty,
        args.autodeploy,
        build_enabled,
    )

    if args.ports:
        c.ports = [args.ports]
    elif args.deploy != DeployType.NO_DEPLOY:
        c.ports = [1337]

    conflict, reason = ChallengeUtils.validate_name(c)
    if not conflict:
        print("Error: " + reason)
        exit()

    conflict = ChallengeUtils.validate_flag(c.flag)
    if not conflict:
        print("Error: " + r"Flag does not match ^bctf\{.*\}$")
        exit()

    conflict = ChallengeUtils.generate(c)
    if conflict:
        print(f"Done. Run `git switch -c {c.name}_{c.author}` to switch to a branch and start working.")
    else:
        print("Error: Failed to create challenge.")
