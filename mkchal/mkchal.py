from __future__ import annotations
from enum import Enum
from re import match, sub
from pathlib import Path
from json import dumps, loads
from secrets import token_hex
from os import path as os_path

import argparse

"""
Should be in the structure of
type1: [chal.json1, chal.json2...],
type2: [...],
...
"""
loaded_challs = {}
context = Path(os_path.dirname(os_path.dirname(os_path.abspath(__file__))))
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
        global context
        challenge: Path = context / "src" / challenge_obj.type.value / challenge_obj.name
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
        context_dir = context / "src"
        for dir in context_dir.iterdir():
            if dir.is_dir() and dir.name in d.keys():
                for challenge in dir.iterdir():
                    d[dir.name][challenge.name] = loads((challenge / "chal.json").read_text())
        return d
    
    @staticmethod
    def generate_service_name(name: str) -> str:
        """Ensures uniqueness between challenge service names"""
        return f"{name}-{token_hex(16)}"
    
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
        (challenge / "src").mkdir(parents=True, exist_ok=DEBUG)
        (challenge / "dist").mkdir(parents=True, exist_ok=DEBUG)
        (challenge / "solve").mkdir(parents=True, exist_ok=DEBUG)
        (challenge / "README.md").write_text(challenge_obj.gen_readme())
        (challenge / "chal.json").write_text(str(challenge_obj))
        (challenge / "flag.txt").write_text(challenge_obj.flag)



    @staticmethod
    def __generate_deployments(challenge_obj: Challenge, challenge: Path) -> None:
        if challenge_obj.deploy != DeployType.NO_DEPLOY:
            (challenge / "deploy").mkdir(parents=True, exist_ok=DEBUG)
            (challenge / "deploy" / "Dockerfile").write_text(challenge_obj.gen_dockerfile())
            (challenge / "deploy" / "wrapper.sh").write_text(challenge_obj.gen_wrapper())

            if challenge_obj.type == ChallengeType.PWN:
                # special build Dockerfile and redpwn jail for pwn
                (challenge / "src" / "sample.c").write_text(challenge_obj.gen_sample())
                (challenge / "src" / "build.sh").write_text(challenge_obj.gen_pwn_build_script())
                (challenge / "deploy" / "Dockerfile_build").write_text(challenge_obj.gen_pwn_dockerfile_build())

                # for now pwn only support docker-compose
                assert challenge_obj.deploy == DeployType.DOCKER_COMPOSE
                (challenge / "deploy" / "docker-compose.yml").write_text(challenge_obj.gen_docker_compose())
                (challenge / "build_dist.sh").write_text(challenge_obj.gen_pwn_build_dist())
                (challenge / "run.sh").write_text(f"#!/bin/bash\nexport CHALL_HASH='{ChallengeUtils.generate_service_name(challenge_obj.name)}' # please leave this line in\ncd deploy && sudo -E docker-compose up -d --build {ChallengeUtils.safe_name(challenge_obj.name)}")
            else:
                (challenge / "src" / "sample.py").write_text(challenge_obj.gen_sample())
                if challenge_obj.deploy == DeployType.DOCKER_COMPOSE:
                    (challenge / "deploy" / "docker-compose.yml").write_text(challenge_obj.gen_docker_compose())
                    (challenge / "run.sh").write_text(f"#!/bin/bash\nexport CHALL_HASH='{ChallengeUtils.generate_service_name(challenge_obj.name)}' # please leave this line in\ncd deploy && sudo -E docker-compose up -d --build")
                elif challenge_obj.deploy == DeployType.KLODD:
                    (challenge / "deploy" / "challenge.yml").write_text(challenge_obj.gen_klodd_challenge())
                    (challenge / "run.sh").write_text(f"#!/bin/bash\nexport CHALL_HASH='{ChallengeUtils.generate_service_name(challenge_obj.name)}' # please leave this line in\ncd deploy && sudo -E docker build . -t{ChallengeUtils.safe_name(challenge_obj.name)} && sudo -E docker push {challenge_obj.registry}/{ChallengeUtils.safe_name(challenge_obj.name)} && kubectl create -f challenge.yml")

class Challenge:
    """Represents a challenge object"""

    __slots__ = ["name", "author", "description", "flag", "type", "deploy", "ports", "hidden", "minPoints", "maxPoints", "tiebreakEligible", "prereqs", "tags", "difficulty", "auto", "registry"]
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
        self.registry = "localhost:5000"
    
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

 - `./run.sh` will run your challenge using the binary in dist.

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
### {self.name}/run.sh 
**IMPORTANT**: If your challenge is not deployed via Klodd, ensure it can be fully deployed by running:
```bash
./run.sh
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
        if self.type == ChallengeType.WEB:
            return ChallengeUtils.generate_file_content(context / "mkchal" / "templates" / "web" / "Dockerfile", kwargs)
        elif self.type == ChallengeType.PWN:
            return ChallengeUtils.generate_file_content(context / "mkchal" / "templates" / "pwn" / "Dockerfile", kwargs)
        return ChallengeUtils.generate_file_content(context / "mkchal" / "templates" / "Dockerfile", kwargs)
        
    
    def gen_docker_compose(self) -> str:
        """Generates a sample docker-compose.yml"""
        safe_name = ChallengeUtils.safe_name(self.name)
        kwargs = {
            "name": safe_name,
            "hash": ChallengeUtils.generate_service_name(safe_name),
            "port": self.ports[0]
        }
        if self.type == ChallengeType.WEB:
            return ChallengeUtils.generate_file_content(context / "mkchal" / "templates" / "web" / "docker-compose.yml", kwargs)
        elif self.type == ChallengeType.PWN:
            return ChallengeUtils.generate_file_content(context / "mkchal" / "templates" / "pwn" / "docker-compose.yml", kwargs)
        return ChallengeUtils.generate_file_content(context / "mkchal" / "templates" / "docker-compose.yml", kwargs)
    
    def gen_wrapper(self) -> str:
        """Generates a sample wrapper.sh"""
        
        safe_name = ChallengeUtils.safe_name(self.name)
        kwargs = {
            "name": safe_name
        }
        if self.type == ChallengeType.WEB:
            return ChallengeUtils.generate_file_content(context / "mkchal" / "templates" / "web" / "wrapper.sh", kwargs)
        elif self.type == ChallengeType.PWN:
            return ChallengeUtils.generate_file_content(context / "mkchal" / "templates" / "pwn" / "wrapper.sh", kwargs)
        return ChallengeUtils.generate_file_content(context / "mkchal" / "templates" / "wrapper.sh", kwargs)
    
    def gen_sample(self) -> str:
        """Generates the sample challenge file"""

        kwargs = {
            "name": self.name,
            "port": self.ports[0]
        }
        if self.type == ChallengeType.WEB:
            return ChallengeUtils.generate_file_content(context / "mkchal" / "templates" / "web" / "sample.py", kwargs)
        elif self.type == ChallengeType.PWN:
            return ChallengeUtils.generate_file_content(context / "mkchal" / "templates" / "pwn" / "sample.c", kwargs)
        return ChallengeUtils.generate_file_content(context / "mkchal" / "templates" / "sample.py", kwargs)
    
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
            return ChallengeUtils.generate_file_content(context / "mkchal" / "templates" / "web" / "challenge.yml", kwargs)
        return ChallengeUtils.generate_file_content(context / "mkchal" / "templates" / "challenge.yml", kwargs)

    def gen_pwn_build_script(self) -> str:
        """Generates build.sh build script for pwn challenges"""
        safe_name = ChallengeUtils.safe_name(self.name)
        kwargs = {
            "name": safe_name,
            "port": self.ports[0]
        }

        assert self.type == ChallengeType.PWN
        return ChallengeUtils.generate_file_content(context / "mkchal" / "templates" / "pwn" / "build.sh", kwargs)

    def gen_pwn_dockerfile_build(self) -> str:
        """Genrates Dockerfile_build for building pwn dockerfiles"""
        safe_name = ChallengeUtils.safe_name(self.name)
        kwargs = {
            "name": safe_name,
            "hash": ChallengeUtils.generate_service_name(safe_name),
            "port": self.ports[0]
        }

        assert self.type == ChallengeType.PWN
        return ChallengeUtils.generate_file_content(context / "mkchal" / "templates" / "pwn" / "Dockerfile_build", kwargs)

    def gen_pwn_build_dist(self) -> str:
        """Genrates build_dist.sh for building pwn dockerfiles"""
        safe_name = ChallengeUtils.safe_name(self.name)
        kwargs = {
            "name": safe_name,
            "port": self.ports[0],
            "hash": ChallengeUtils.generate_service_name(safe_name)
        }

        assert self.type == ChallengeType.PWN
        return ChallengeUtils.generate_file_content(context / "mkchal" / "templates" / "pwn" / "build_dist.sh", kwargs)
    
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
