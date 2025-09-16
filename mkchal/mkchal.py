from __future__ import annotations

import os
import stat
from enum import Enum
from json import dumps, loads
from pathlib import Path
from re import match, sub
from secrets import token_hex

# Infra constants
ROOT_DOMAIN = os.getenv("ROOT_DOMAIN", "b01le.rs") # TODO: make it compliant with the testing workflow and VPS
HTTP_ENTRY = 443
TCP_SEC_ENTRY = 8443
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
COMPOSE_PROD = "docker-compose.prod.yml"
WRAPPER = "wrapper.sh"
SAMPLE_PY = "sample.py"
SAMPLE_C = "sample.c"
KLODD_YAML = "challenge.yml"
BUILD_SH = "build.sh"
DOCKERFILE_BUILD = "Dockerfile_build"
BUILD_DIST = "build_dist.sh"
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


import argparse

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

SPECIAL_CHAL_TYPES = (ChallengeType.WEB, ChallengeType.PWN)

def make_file_executable(path: Path):
    st = os.stat(path)
    os.chmod(path, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

class ChallengeUtils:

    @staticmethod
    def validate_name(challenge: Challenge) -> tuple[bool, str]:
        """Validates a challenge name"""

        if len(loaded_challs.keys()) < 1:
            return (False, "Unloaded challs")
        for chall_name in loaded_challs[challenge.type.value].keys():
            if ChallengeUtils.safe_name(challenge.name) == ChallengeUtils.safe_name(chall_name):
                return (False, f"Name {challenge.name} conficts with challenge {chall_name} in category {challenge.type.value}")
        return (True, "success")
    
    @staticmethod
    def validate_flag(flag: str) -> bool:
        """Validates whether a flag fits the required format"""

        return match(r"^bctf\{.*\}$", flag) != None
    
    @staticmethod
    def generate(challenge_obj: Challenge) -> bool:
        """Generates a challenge. Assumes valid fields"""
        challenge: Path = SRC_DIR / challenge_obj.type.value / challenge_obj.name
        challenge.mkdir(parents=True, exist_ok=DEBUG)
        ChallengeUtils.__generate_defaults(challenge_obj, challenge)
        ChallengeUtils.__generate_deployments(challenge_obj, challenge)
        return True

    @staticmethod
    def retrieve_valid_port(type: ChallengeType) -> tuple[bool, int]:
        """returns: (success, port)"""
        #TODO create server on b01lers server that generates a valid port
        # We let the user choose a port for now, with traefik this shouldn't be needed
        return (False, 0)
    
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
            "osint": {}
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
        
        return sub(r"^-+|-+$", "", sub(r"[^a-z0-9-]", "", name.lower()))
    
    @staticmethod
    def __generate_defaults(challenge_obj: Challenge, challenge: Path) -> None:
        (challenge / SRC).mkdir(parents=True, exist_ok=DEBUG)
        (challenge / DIST).mkdir(parents=True, exist_ok=DEBUG)
        (challenge / SOLVE).mkdir(parents=True, exist_ok=DEBUG)
        (challenge / README).write_text(challenge_obj.gen_readme())
        (challenge / CHAL_JSON).write_text(str(challenge_obj))
        (challenge / FLAG).write_text(challenge_obj.flag)

    @staticmethod
    def __generate_deployments(challenge_obj: Challenge, challenge: Path) -> None:
        if challenge_obj.deploy == DeployType.NO_DEPLOY:
            return
        
        (challenge / DEPLOY).mkdir(parents=True, exist_ok=DEBUG)
        (challenge / DEPLOY / DOCKERFILE).write_text(challenge_obj.gen_dockerfile())
        (challenge / DEPLOY / COMPOSE).write_text(challenge_obj.gen_docker_compose())
        (challenge / DEPLOY / COMPOSE_PROD).write_text(
            ChallengeUtils.generate_file_content(TEMPLATES_DIR / COMPOSE_PROD, {})
        )
        (challenge / DEPLOY / WRAPPER).write_text(challenge_obj.gen_wrapper())

        (challenge / RUN_SH).write_text(challenge_obj.gen_run_sh())
        (challenge / DEV_SH).write_text(challenge_obj.gen_dev_sh())
        make_file_executable(challenge / RUN_SH)
        make_file_executable(challenge / DEV_SH)
        
        if challenge_obj.type == ChallengeType.PWN:
            # special build Dockerfile and redpwn jail for pwn
            (challenge / SRC / SAMPLE_C).write_text(challenge_obj.gen_sample())
            (challenge / SRC / BUILD_SH).write_text(challenge_obj.gen_pwn_build_script())
            make_file_executable(challenge / SRC / BUILD_SH)
            (challenge / DEPLOY / DOCKERFILE_BUILD).write_text(challenge_obj.gen_pwn_dockerfile_build())

            # for now pwn only support docker-compose
            assert challenge_obj.deploy == DeployType.DOCKER_COMPOSE
            (challenge / BUILD_DIST).write_text(challenge_obj.gen_pwn_build_dist())
            make_file_executable(challenge / BUILD_DIST)
            
            return

        (challenge / SRC / SAMPLE_PY).write_text(challenge_obj.gen_sample())
        
        if challenge_obj.deploy == DeployType.KLODD:
            #TODO: b01lers kube interface would be different, wait for vinh's decision
            (challenge / DEPLOY / KLODD_YAML).write_text(challenge_obj.gen_klodd_challenge())

class Challenge:
    """Represents a challenge object"""

    __slots__ = ["name", "author", "description", "flag", "type", "deploy", "ports", "hidden", "minPoints", "maxPoints", "tiebreakEligible", "prereqs", "tags", "difficulty", "auto", "registry", "root_domain"]
    optional_fields = ["ports", "hidden", "minPoints", "maxPoints", "tiebreakEligible", "prereqs", "tags"]
    
    def __init__(self, name: str, author: str, description: str, flag: str, type: ChallengeType, deploy: DeployType, difficulty: ChallengeDifficulty, auto:bool=False) -> None:
        self.name = name
        self.author = author
        self.description = description
        self.flag = flag
        self.type = type
        self.deploy = deploy
        self.ports = []
        self.auto = auto
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
            "can_be_auto_deployed": self.auto
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
        if self.deploy != DeployType.NO_DEPLOY:
            ret += """\n ├── deploy \
            \n │    └──  deployment files  \
            """
        ret += """\n ├── dist \
        \n │    └── files to be given to competitors \
        \n ├── solve \
        \n │    └── writeup and solution scripts \
        \n ├── src \
        \n │    └── challenge source files \
        \n ├── chall.json ── challenge information \
        \n ├── flag.txt ── the flag \
        \n ├── README.md ── this file \
        """
        if self.deploy != DeployType.NO_DEPLOY:
            ret += """\n └── run.sh ── what will be run to deploy your challenge"""
            ret += """\n └── dev.sh ── what you should use to test your challenge"""
        ret += """\n```"""
        ret += f"""\n## Quickstart to challenge development 
Make sure you develop your challenge on a new branch. You can create one with
```bash
git checkout -b {self.name}_{self.author}
```"""
        if self.deploy == DeployType.DOCKER_COMPOSE:
            ret += f"""\n### {self.name}/deploy
The sample deploy folder contains
 - `Dockerfile`: A basic setup for a challenge, accessible at port 1337.
 - `docker-compose.yml`: Defines deployment steps for the challenge.
 - `wrapper.sh`: Wraps the executable by `cd`ing to the correct directory

This setup is well-suited for pwn, reverse engineering, non instanced web challenges, and cryptography challenges requiring a hosted service.

Delete the sample challenge before you start working.

If your challenge allows Remote Code Execution (RCE), it must be sandboxed using either:
 - [nsjail](https://github.com/google/nsjail)
 - [redpwn jail](https://github.com/redpwn/jail).
"""
            
        if self.type == ChallengeType.PWN and self.deploy != DeployType.NO_DEPLOY:
            ret += f"""\n### Build system (for pwn challenges)
The sample files generated for a pwn challenge include a build system which will build your executable and place it in the dist directory.
The sample `Dockerfile` uses this executable in dist to run the challenge.
You should keep this structure the same when you add your challenge as it is important for the Docker container to run the same binary as you give the competitors.

 - `./build_dist.sh` will build your challenge and copy the executable and libc to dist.

 - `./dev.sh` will run your challenge using the binary in dist.

"""

        if self.deploy == DeployType.KLODD:
            ret += f"""\n### {self.name}/deploy
The sample deploy folder contains
- `Dockerfile`: A simple webserver setup designed for deployment with Klodd.
- `challenge.yml`: Configuration file defining Klodd deployment settings.
If you're new to Klodd, avoid modifying these files without checking with the CTF developers.
"""
            
        ret += f"""\n### {self.name}/dist
Contains files distributed to competitors. If multiple files are included, bundle them into a ZIP archive. 
### {self.name}/solve 
Contains the challenge's writeup and solution scripts. A well-documented writeup is crucial for assessing challenge quality. 
### {self.name}/src 
Contains the challenge source files. If deployment is required, the `Dockerfile` should use this folder to build the challenge. Ensure all necessary files are included for proper functionality.
### {self.name}/dev.sh 
**IMPORTANT**: If your challenge is not deployed via Klodd, ensure it can be fully deployed by running:
```bash
./dev.sh
```
## Merging 
Once your challenge is complete, submit a **Pull Request (PR)**. The PR will be merged after a quality review on GitHub.

Before creating a PR please comment out the ports in your docker-compose file.

---
This README was autogenerated by `mkchal.py`, but written by Neil (CygnusX). Suggestions are welcome.
"""
        return ret
    
    def gen_dockerfile(self) -> str:
        """Generates a sample Dockerfile"""

        kwargs = {
            "name": ChallengeUtils.safe_name(self.name),
            "port": self.ports[0]
        }
        if self.type in SPECIAL_CHAL_TYPES:
            return ChallengeUtils.generate_file_content(TEMPLATES_DIR / self.type.value / DOCKERFILE, kwargs)
        return ChallengeUtils.generate_file_content(TEMPLATES_DIR / DOCKERFILE, kwargs)
        
    
    def gen_docker_compose(self) -> str:
        """Generates a sample docker-compose.yml"""
        safe_name = ChallengeUtils.safe_name(self.name)
        kwargs = {
            "name": safe_name,
            "hash": ChallengeUtils.generate_service_name(safe_name),
            "port": self.ports[0],
            "root_domain": self.root_domain
        }
        if self.type in SPECIAL_CHAL_TYPES:
            return ChallengeUtils.generate_file_content(TEMPLATES_DIR / self.type.value / COMPOSE, kwargs)
        return ChallengeUtils.generate_file_content(TEMPLATES_DIR / COMPOSE, kwargs)
    
    def gen_wrapper(self) -> str:
        """Generates a sample wrapper.sh"""
        
        safe_name = ChallengeUtils.safe_name(self.name)
        kwargs = {
            "name": safe_name
        }
        if self.type in SPECIAL_CHAL_TYPES:
            return ChallengeUtils.generate_file_content(TEMPLATES_DIR / self.type.value / WRAPPER, kwargs)
        return ChallengeUtils.generate_file_content(TEMPLATES_DIR / WRAPPER, kwargs)
    
    def gen_sample(self) -> str:
        """Generates the sample challenge file"""

        kwargs = {
            "name": self.name,
            "port": self.ports[0]
        }
        if self.type in SPECIAL_CHAL_TYPES:
            return ChallengeUtils.generate_file_content(TEMPLATES_DIR / self.type.value / (SAMPLE_PY if self.type == ChallengeType.WEB else SAMPLE_C), kwargs)
        return ChallengeUtils.generate_file_content(TEMPLATES_DIR / SAMPLE_PY, kwargs)
    
    def gen_klodd_challenge(self) -> str:
        """Generates a sample challenge.yml"""
        safe_name = ChallengeUtils.safe_name(self.name)
        kwargs = {
            "unsafe_name": self.name,
            "name": safe_name,
            "port": self.ports[0],
            "image": f"{self.registry}/{safe_name}"
        }
        if self.type == ChallengeType.WEB:
            return ChallengeUtils.generate_file_content(TEMPLATES_DIR / self.type.value / KLODD_YAML, kwargs)
        return ChallengeUtils.generate_file_content(TEMPLATES_DIR / KLODD_YAML, kwargs)

    def gen_pwn_build_script(self) -> str:
        """Generates build.sh build script for pwn challenges"""
        safe_name = ChallengeUtils.safe_name(self.name)
        kwargs = {
            "name": safe_name,
            "port": self.ports[0]
        }

        assert self.type == ChallengeType.PWN
        return ChallengeUtils.generate_file_content(PWN_TEMPLATE_DIR / BUILD_SH, kwargs)

    def gen_pwn_dockerfile_build(self) -> str:
        """Genrates Dockerfile_build for building pwn dockerfiles"""
        safe_name = ChallengeUtils.safe_name(self.name)
        kwargs = {
            "name": safe_name,
            "hash": ChallengeUtils.generate_service_name(safe_name),
            "port": self.ports[0]
        }

        assert self.type == ChallengeType.PWN
        return ChallengeUtils.generate_file_content(PWN_TEMPLATE_DIR / DOCKERFILE_BUILD, kwargs)

    def gen_pwn_build_dist(self) -> str:
        """Genrates build_dist.sh for building pwn dockerfiles"""
        safe_name = ChallengeUtils.safe_name(self.name)
        kwargs = {
            "name": safe_name,
            "port": self.ports[0],
            "hash": ChallengeUtils.generate_service_name(safe_name)
        }

        assert self.type == ChallengeType.PWN
        return ChallengeUtils.generate_file_content(PWN_TEMPLATE_DIR / BUILD_DIST, kwargs)
    
    def gen_run_sh(self):
        safe_name = ChallengeUtils.safe_name(self.name)
        subdomain = ChallengeUtils.generate_service_name(safe_name)
        kwargs = {
            "name": safe_name,
            "remote_command": (
                f"curl https://{subdomain}.{ROOT_DOMAIN}"
                if self.type == ChallengeType.WEB 
                else f"ncat --ssl {subdomain}.{ROOT_DOMAIN} {TCP_SEC_ENTRY}"
            ),
            "registry": self.registry
        }
        if self.type == ChallengeType.WEB and self.deploy == DeployType.KLODD:
            return ChallengeUtils.generate_file_content(TEMPLATES_DIR / self.type.value / "klodd" / RUN_SH, kwargs)
        return ChallengeUtils.generate_file_content(TEMPLATES_DIR / RUN_SH, kwargs)
    
    def gen_dev_sh(self):
        safe_name = ChallengeUtils.safe_name(self.name)
        kwargs = {
            "name": safe_name,
            "local_command": (
                "curl http://localhost:1337"
                if self.type == ChallengeType.WEB 
                else "ncat localhost 1337"
            )
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
    parser = argparse.ArgumentParser(prog='mkchal', description='Creates a sample challenge for a ctf')

    parser.add_argument(
        "--name",
        type=str,
        required=True,
        help="The name of the challenge."
    )

    parser.add_argument(
        "--desc",
        type=str,
        required=True,
        help="The description of the challenge."
    )

    parser.add_argument(
        "--author",
        type=str,
        required=True,
        help="The author of the challenge."
    )

    parser.add_argument(
        "--flag",
        type=str,
        required=True,
        help="The challenge flag."
    )

    parser.add_argument(
        "--type",
        type=ChallengeType,
        required=True,
        choices=[c.value for c in ChallengeType],
        help="The type of the challenge."
    )

    parser.add_argument(
        "--deploy",
        type=DeployType,
        required=True,
        choices=[c.value for c in DeployType],
        help="How the challenge will be deployed"
    )

    parser.add_argument(
        "--ports",
        nargs="+",
        type=int,
        required=False,
        help="The ports that the challenge runs on inside the container.",
    )

    parser.add_argument(
        "--autodeploy",
        type=bool,
        required=True,
        choices=[b for b in [False, True]],
        help="Whether or not the challenge can be automatically deployed.",
    )

    parser.add_argument(
        "--difficulty",
        type=ChallengeDifficulty,
        required=True,
        choices=[c.value for c in ChallengeDifficulty],
        help="The challenge difficulty.",
    )

    args = parser.parse_args()

    c = Challenge(
        ChallengeUtils.safe_name(args.name),
        args.author,
        args.desc, 
        args.flag,
        args.type,
        args.deploy,
        args.difficulty,
        args.autodeploy)
    
    if args.ports:
        c.ports = args.ports
    elif args.deploy != DeployType.NO_DEPLOY:
        print("Error: deploy with no ports")
        exit()

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
        print(f"Done. Run `git checkout -b {c.name}_{c.author}` to switch to a branch and start working.")
    else:
        print("Error: Failed to create challenge.")
