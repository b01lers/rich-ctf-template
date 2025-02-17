from __future__ import annotations
from enum import Enum
from re import match
from pathlib import Path
from json import dumps
from secrets import token_hex

import os

"""
Should be in the structure of
type1: [chal.json1, chal.json2...],
type2: [...],
...
"""
loaded_challs = {}
context = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEBUG = True #TODO Change this to false when script is done

class ChallengeType(str, Enum):
    """Describes a CTF challenge type."""

    REV = "rev"
    PWN = "pwn"
    CRYPTO = "crypto"
    WEB = "web"
    MISC = "misc"
    BLOCKCHAIN = "blockchain"
    OSINT = "osint"

class DeployType(str, Enum):
    """Describes a deployment type."""

    DOCKER_COMPOSE = "docker-compose"
    KLODD = "klodd"
    NO_DEPLOY = "None"

class ChallengeUtils:

    @staticmethod
    def validate_name(name: str) -> tuple[bool, str]:
        """Validates a challenge name"""

        if len(loaded_challs.keys()) < 1:
            return (False, "Unloaded challs")
        for type in loaded_challs.values():
            for chall in type:
                if chall["name"] == name:
                    return (False, f"Name {name} conflicts with {chall['name']} by {chall['author']} in {type}")
        return (True, "success")
    
    @staticmethod
    def validate_flag(flag: str) -> bool:
        """Validates whether a flag fits the required format"""

        return match(r"^bctf\{.*\}$", flag) != None
    
    @staticmethod
    def generate(challenge_obj: Challenge) -> bool:
        """Generates a challenge. Assumes valid fields"""
        global context
        challenge: Path = context / challenge_obj.type.value / challenge_obj.name
        challenge.mkdir(parents=True, exist_ok=DEBUG)
        ChallengeUtils.__generate_defaults(challenge_obj, challenge)
        ChallengeUtils.__generate_deployments(challenge_obj, challenge)
        return True

    @staticmethod
    def retrieve_valid_port(type: ChallengeType) -> tuple[bool, int]:
        """returns: (success, port)"""
        #TODO create server on b01lers server that generates a valid port
        return (False, 0)
    
    @staticmethod
    def load_challenges() -> dict:
        """
        Loads all currently created challenges into a dict.
        Assumes proper directory structure.
        """
        return {}
    
    @staticmethod
    def generate_service_name(challenge: Challenge) -> str:
        """Ensures uniqueness between challenge service names"""
        return f"{challenge.name}-{token_hex(16)}"
    
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
        if not challenge_obj.deploy == DeployType.NO_DEPLOY:
            (challenge / "deploy").mkdir(parents=True, exist_ok=DEBUG)
        if challenge_obj.deploy == DeployType.DOCKER_COMPOSE:
            (challenge / "deploy" / "Dockerfile").touch(exist_ok=DEBUG)
            (challenge / "deploy" / "docker-compose.yml").touch(exist_ok=DEBUG)
            (challenge / "deploy" / "wrapper.sh").touch(exist_ok=DEBUG)
            (challenge / "run.sh").write_text("#!/bin/bash\ncd ../deploy && sudo docker-compose up -d --build")
        elif challenge_obj.deploy == DeployType.KLODD:
            (challenge / "deploy" / "Dockerfile").touch(exist_ok=DEBUG)
            (challenge / "deploy" / "challenge.yml").touch(exist_ok=DEBUG)
            (challenge / "deploy" / "wrapper.sh").touch(exist_ok=DEBUG)
            (challenge / "run.sh").write_text("#!/bin/bash\ncd ../deploy && kubectl create -f challenge.yml")

class Challenge:
    """Represents a challenge object"""

    __slots__ = ["name", "author", "description", "flag", "type", "deploy", "ports", "hidden", "minPoints", "maxPoints", "tiebreakEligible", "prereqs", "tags", "difficulty", "auto"]
    optional_fields = ["ports", "hidden", "minPoints", "maxPoints", "tiebreakEligible", "prereqs", "tags", "difficulty"]
    
    def __init__(self, name: str, author: str, description: str, flag: str, type: ChallengeType, deploy: DeployType, auto:bool=False) -> None:
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
        self.difficulty = None
    
    def to_json(self) -> dict:
        """converts a challenge to its valid chal.json output"""
        d: dict = {
            "name": self.name,
            "author": self.author,
            "description": self.description,
            "flag": self.flag,
            "can_be_auto_deployed": self.auto
        }
        for field in self.optional_fields:
            val = getattr(self, field)
            if isinstance(val, list) and len(val) > 0 or val is not None and not isinstance(val, list):
                d[field] = val
        return d
    
    def gen_readme(self) -> str:
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
Make sure you develop your challenge on a new branch. You can create one with `git checkout -b {self.name}-{self.author}`"""
        if self.deploy == DeployType.DOCKER_COMPOSE:
            ret += f"""\n### {self.name}/deploy \
            \nThe deploy folder contains `Dockerfile`, `docker-compose.yml` and `wrapper.sh` files. The sample `Dockerfile` is for a simple tcp challenge servable through \
netcat. This setup is perfect for basic pwn, rev, or crypto challenges that need a deployment. The sample `docker-compose.yml` contains deployment steps \
for your challenge. `wrapper.sh` is a sample script which will be served by socat in the `Dockerfile`. The deployment files can and (most likely) will be changed by you. 

If you are creating a pwn challenge, or any challenge where the competitor might get RCE, it is required to instance your challenge through either \
[nsjail](https://github.com/google/nsjail), or [redpwn jail](https://github.com/redpwn/jail)."""
        if self.deploy == DeployType.KLODD:
            ret += f"""\n### {self.name}/deploy \
            \nThe deploy folder contains `Dockerfile`, `challenge.yml` files. The sample `Dockerfile` is for a simple webserver that will be instanced \
using [klodd](https://klodd.tjcsec.club/). `application.yml` contains the necessary klodd deployment information. If you are unfamiliar with klodd deployments please don't change anything and \
ask in the ctf developer channel."""
            
        ret += f"""\n### {self.name}/dist \
        \nThe dist folder is for files to be given to the competitors. If you have more than one distribution file, please place them in a zip or archive folder. \
        \n### {self.name}/solve \
        \nThe solve folder is for your challenge writeup and solution scripts. Make sure the writeup is detailed. Challenge quality might be assessed through your writeup.
        \n### {self.name}/src \
        \nThe src folder is for your challenge source and should be used by your Dockerfile to build your challenge if your challenge needs to be deployed.
Make sure this folder contains all necesary files so your challenge works properly.
        \n### {self.name}/run.sh \
        \n**IMPORTANT** Unless your challenge is deployed through Klodd, please make sure your challenge is entirely deployable by running `./run.sh`
        \n## Merging \
        \nWhen you have finished challenge development, please create a PR which will be merged after quality checks on the github.\
        \n\n---\
        \nThis README was autogenerated by mkchal.py, but written by Neil. Suggestions are welcome.
        """
        return ret
    
    def create(self) -> bool:
        """Creates the challenge structure for a challenge"""
        return ChallengeUtils.generate(self)
    
    def __repr__(self) -> str:
        return dumps(self.to_json(), indent=4)
    

if __name__ == "__main__":
    loaded_challs = ChallengeUtils.load_challenges()
    c = Challenge("Amazing Challenge", "CygnusX-26", "An amazing sample challenge with an equally amazing description", "bctf{amazing_flag_moment}", ChallengeType.BLOCKCHAIN, DeployType.DOCKER_COMPOSE)
    c.difficulty = "Easy"
    c.hidden = True
    c.maxPoints = 1
    c.minPoints = 1
    c.ports = [4000, 4001]
    # c.hidden = True
    # print(c.to_json())
    print(ChallengeUtils.generate(c))