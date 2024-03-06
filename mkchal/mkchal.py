from pathlib import Path
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional
from json import loads, dumps
from rich.console import Console
from os.path import isdir


class Type(str, Enum):
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


@dataclass
class Challenge:
    """Represents a CTF challenge."""

    type: Type
    name: str
    author: str
    description: str
    difficulty: str
    flag: str
    provides: List[str]
    ports: List[int]
    remote: Optional[List[str]]


class ChallengeManager:
    """Manages CTF challenges."""

    def __init__(self) -> None:
        self.challenges: List[Challenge] = []

    @staticmethod
    def create_rev(name, author, description, difficulty, flag, deploy):
        deploy = True if deploy == "y" else False
        console = Console()
        console.print("Creating rev challenge", style="bold green")
        tld = Path.cwd()
        rev = tld / "rev"
        rev.mkdir(exist_ok=True)
        challenge = rev / name
        challenge.mkdir(exist_ok=True)
        (challenge / "src").mkdir(exist_ok=True)
        (challenge / "deploy" ).mkdir(exist_ok=True)
        (challenge / "dist").mkdir(exist_ok=True)
        (challenge / "chal.json").touch()
        with open(challenge / "chal.json", "w") as f:
            f.write(dumps({
                "name": name,
                "author": author,
                "description": description,
                "difficulty": difficulty,
                "flag": flag,
                "ports": [],
                "can_be_auto_deployed": deploy
            }, indent=4))
        with open(challenge / "run.sh", "w") as f:
            f.write("#!/bin/bash\n")
            f.write("cd ./deploy\n")
            f.write("sudo docker-compose up --build -d\n")
        with open(challenge / "deploy" / "Dockerfile", "w") as f:
            f.write("#put your dockerfile contents here\n")
        with open(challenge / "deploy" / "docker-compose.yml", "w") as f:
            f.write("#put your docker-compose contents here\n")
        with open(challenge / "flag.txt" , "w") as f:
            f.write(flag)
        with open(challenge / "dist" / "flag.txt" , "w") as f:
            f.write('fake{flag}')
        with open(challenge / "README.md" , "w") as f:
            f.write(f'# Writeup for {name} by {author}')
            f.write('\n\n')
            f.write('## Add your writeup here!')
        __import__("time").sleep(2) # scuffed way to make sure stuff worked
        console.print("\nDone.", style="bold red")

    @staticmethod
    def create_pwn(name, author, description, difficulty, flag, deploy):
        deploy = True if deploy == "y" else False
        console = Console()
        console.print("Creating pwn challenge", style="bold green")
        tld = Path.cwd()
        rev = tld / "pwn"
        rev.mkdir(exist_ok=True)
        challenge = rev / name
        challenge.mkdir(exist_ok=True)
        (challenge / "src").mkdir(exist_ok=True)
        (challenge / "deploy" ).mkdir(exist_ok=True)
        (challenge / "dist").mkdir(exist_ok=True)
        (challenge / "chal.json").touch()
        with open(challenge / "chal.json", "w") as f:
            f.write(dumps({
                "name": name,
                "author": author,
                "description": description,
                "difficulty": difficulty,
                "flag": flag,
                "ports": [],
                "can_be_auto_deployed": deploy
            }, indent=4))
        with open(challenge / "run.sh", "w") as f:
            f.write("#!/bin/bash\n")
            f.write("cd ./deploy\n")
            f.write("sudo docker-compose up --build -d\n")
        with open(challenge / "deploy" / "Dockerfile", "w") as f:
            f.write("#put your dockerfile contents here\n")
        with open(challenge / "deploy" / "docker-compose.yml", "w") as f:
            f.write("#put your docker-compose contents here\n")
        with open(challenge / "flag.txt" , "w") as f:
            f.write(flag)
        with open(challenge / "dist" / "flag.txt" , "w") as f:
            f.write('fake{flag}')
        with open(challenge / "README.md" , "w") as f:
            f.write(f'# Writeup for {name} by {author}')
            f.write('\n\n')
            f.write('## Add your writeup here!')
        __import__("time").sleep(2) # scuffed way to make sure stuff worked
        console.print("\nDone.", style="bold red")

    @staticmethod
    def create_crypto(name, author, description, difficulty, flag, deploy):
        deploy = True if deploy == "y" else False
        console = Console()
        console.print("Creating crypto challenge", style="bold green")
        tld = Path.cwd()
        rev = tld / "crypto"
        rev.mkdir(exist_ok=True)
        challenge = rev / name
        challenge.mkdir(exist_ok=True)
        (challenge / "src").mkdir(exist_ok=True)
        (challenge / "deploy" ).mkdir(exist_ok=True)
        (challenge / "dist").mkdir(exist_ok=True)
        (challenge / "chal.json").touch()
        with open(challenge / "chal.json", "w") as f:
            f.write(dumps({
                "name": name,
                "author": author,
                "description": description,
                "difficulty": difficulty,
                "flag": flag,
                "ports": [],
                "can_be_auto_deployed": deploy
            }, indent=4))
        with open(challenge / "run.sh", "w") as f:
            f.write("#!/bin/bash\n")
            f.write("cd ./deploy\n")
            f.write("sudo docker-compose up --build -d\n")
        with open(challenge / "deploy" / "Dockerfile", "w") as f:
            f.write("#put your dockerfile contents here\n")
        with open(challenge / "deploy" / "docker-compose.yml", "w") as f:
            f.write("#put your docker-compose contents here\n")
        with open(challenge / "flag.txt" , "w") as f:
            f.write(flag)
        with open(challenge / "dist" / "flag.txt" , "w") as f:
            f.write('fake{flag}')
        with open(challenge / "README.md" , "w") as f:
            f.write(f'# Writeup for {name} by {author}')
            f.write('\n\n')
            f.write('## Add your writeup here!')
        __import__("time").sleep(2) # scuffed way to make sure stuff worked
        console.print("\nDone.", style="bold red")

    @staticmethod
    def create_web(name, author, description, difficulty, flag, deploy):
        deploy = True if deploy == "y" else False
        console = Console()
        console.print("Creating web challenge", style="bold green")
        tld = Path.cwd()
        rev = tld / "web"
        rev.mkdir(exist_ok=True)
        challenge = rev / name
        challenge.mkdir(exist_ok=True)
        (challenge / "src").mkdir(exist_ok=True)
        (challenge / "deploy" ).mkdir(exist_ok=True)
        (challenge / "dist").mkdir(exist_ok=True)
        (challenge / "chal.json").touch()
        with open(challenge / "chal.json", "w") as f:
            f.write(dumps({
                "name": name,
                "author": author,
                "description": description,
                "difficulty": difficulty,
                "flag": flag,
                "ports": [],
                "can_be_auto_deployed": deploy
            }, indent=4))
        with open(challenge / "run.sh", "w") as f:
            f.write("#!/bin/bash\n")
            f.write("cd ./deploy\n")
            f.write("sudo docker-compose up --build -d\n")
        with open(challenge / "deploy" / "Dockerfile", "w") as f:
            f.write("#put your dockerfile contents here\n")
        with open(challenge / "deploy" / "docker-compose.yml", "w") as f:
            f.write("#put your docker-compose contents here\n")
        with open(challenge / "flag.txt" , "w") as f:
            f.write(flag)
        with open(challenge / "dist" / "flag.txt" , "w") as f:
            f.write('fake{flag}')
        with open(challenge / "README.md" , "w") as f:
            f.write(f'# Writeup for {name} by {author}')
            f.write('\n\n')
            f.write('## Add your writeup here!')
        __import__("time").sleep(2) # scuffed way to make sure stuff worked
        console.print("\nDone.", style="bold red")

    @staticmethod
    def create_misc(name, author, description, difficulty, flag, deploy):
        deploy = True if deploy == "y" else False
        console = Console()
        console.print("Creating misc challenge", style="bold green")
        tld = Path.cwd()
        rev = tld / "misc"
        rev.mkdir(exist_ok=True)
        challenge = rev / name
        challenge.mkdir(exist_ok=True)
        (challenge / "src").mkdir(exist_ok=True)
        (challenge / "deploy" ).mkdir(exist_ok=True)
        (challenge / "dist").mkdir(exist_ok=True)
        (challenge / "chal.json").touch()
        with open(challenge / "chal.json", "w") as f:
            f.write(dumps({
                "name": name,
                "author": author,
                "description": description,
                "difficulty": difficulty,
                "flag": flag,
                "ports": [],
                "can_be_auto_deployed": deploy
            }, indent=4))
        with open(challenge / "run.sh", "w") as f:
            f.write("#!/bin/bash\n")
            f.write("cd ./deploy\n")
            f.write("sudo docker-compose up --build -d\n")
        with open(challenge / "deploy" / "Dockerfile", "w") as f:
            f.write("#put your dockerfile contents here\n")
        with open(challenge / "deploy" / "docker-compose.yml", "w") as f:
            f.write("#put your docker-compose contents here\n")
        with open(challenge / "flag.txt" , "w") as f:
            f.write(flag)
        with open(challenge / "dist" / "flag.txt" , "w") as f:
            f.write('fake{flag}')
        with open(challenge / "README.md" , "w") as f:
            f.write(f'# Writeup for {name} by {author}')
            f.write('\n\n')
            f.write('## Add your writeup here!')
        __import__("time").sleep(2) # scuffed way to make sure stuff worked
        console.print("\nDone.", style="bold red")

    @staticmethod
    def create_blockchain(name, author, description, difficulty, flag, deploy):
        deploy = True if deploy == "y" else False
        console = Console()
        console.print("Creating blockchain challenge", style="bold green")
        tld = Path.cwd()
        rev = tld / "blockchain"
        rev.mkdir(exist_ok=True)
        challenge = rev / name
        challenge.mkdir(exist_ok=True)
        (challenge / "src").mkdir(exist_ok=True)
        (challenge / "deploy" ).mkdir(exist_ok=True)
        (challenge / "dist").mkdir(exist_ok=True)
        (challenge / "chal.json").touch()
        with open(challenge / "chal.json", "w") as f:
            f.write(dumps({
                "name": name,
                "author": author,
                "description": description,
                "difficulty": difficulty,
                "flag": flag,
                "ports": [],
                "can_be_auto_deployed": deploy
            }, indent=4))
        with open(challenge / "run.sh", "w") as f:
            f.write("#!/bin/bash\n")
            f.write("cd ./deploy\n")
            f.write("sudo docker-compose up --build -d\n")
        with open(challenge / "deploy" / "Dockerfile", "w") as f:
            f.write("#put your dockerfile contents here\n")
        with open(challenge / "deploy" / "docker-compose.yml", "w") as f:
            f.write("#put your docker-compose contents here\n")
        with open(challenge / "flag.txt" , "w") as f:
            f.write(flag)
        with open(challenge / "dist" / "flag.txt" , "w") as f:
            f.write('fake{flag}')
        __import__("time").sleep(2)
        with open(challenge / "README.md" , "w") as f:
            f.write(f'# Writeup for {name} by {author}')
            f.write('\n\n')
            f.write('## Add your writeup here!')
        console.print("\nDone.", style="bold red")

    @staticmethod
    def create_osint(name, author, description, difficulty, flag):
        console = Console()
        console.print("Creating osint challenge", style="bold green")
        tld = Path.cwd()
        rev = tld / "osint"
        rev.mkdir(exist_ok=True)
        challenge = rev / name
        challenge.mkdir(exist_ok=True)
        (challenge / "dist").mkdir(exist_ok=True)
        (challenge / "chal.json").touch()
        with open(challenge / "chal.json", "w") as f:
            f.write(dumps({
                "name": name,
                "author": author,
                "description": description,
                "difficulty": difficulty,
                "flag": flag,
                "ports": [],
                "can_be_auto_deployed": False
            }, indent=4))
        with open(challenge / "flag.txt" , "w") as f:
            f.write(flag)
        with open(challenge / "README.md" , "w") as f:
            f.write(f'# Writeup for {name} by {author}')
            f.write('\n\n')
            f.write('## Add your writeup here!')
        __import__("time").sleep(2)
        console.print("\nDone.", style="bold red")

    @staticmethod
    def check_name_exists(name, type):
        tld = Path.cwd()
        if type == "1":
            type = "rev"
        elif type == "2":
            type = "pwn"
        elif type == "3":
            type = "crypto"
        elif type == "4":
            type = "web"
        elif type == "5":
            type = "misc"
        elif type == "6":
            type = "blockchain"
        elif type == "7":
            type = "osint"
        if (tld / type / name).exists():
            return True
        return False
        


if __name__ == "__main__":
    console = Console()
    console.clear()
    console.print("> Build ctf challenge direcory structure [Use when setting up repo] (1)", style="red")
    console.print("> Make challenge [Builds a template for your challenge] (2)", style="bold blue")
    console.print("Input 1 or 2", style="blue")
    res = input()
    if res == "1":
        console.print("Building ctf challenge directory structure", style="bold green")
        tld = Path.cwd()
        with console.status("Building ctf challenge directory structure") as status:
            for challenge_type in Type:
                (tld / challenge_type.value).mkdir(exist_ok=True)
                console.log(f"{challenge_type.name} dir made")
        console.print("Done.", style="bold red")
        exit(0)
    elif res == "2":
        console.clear()
        console.print("[bold blue]Challenge Type?")
        console.print("[bold cyan]>[/bold cyan] rev (1)", style="bold green")
        console.print("[bold cyan]>[/bold cyan] pwn (2)", style="bold green")
        console.print("[bold cyan]>[/bold cyan] crypto (3)", style="bold green")
        console.print("[bold cyan]>[/bold cyan] web (4)", style="bold green")
        console.print("[bold cyan]>[/bold cyan] misc (5)", style="bold green")
        console.print("[bold cyan]>[/bold cyan] blockchain (6)", style="bold green")
        console.print("[bold cyan]>[/bold cyan] osint (7)", style="bold green")
        console.print("Input [1-7]", style="blue")
        type = input()
        if type not in ["1", "2", "3", "4", "5", "6", "7"]:
            console.print("Invalid input", style="bold red")
            exit(1)
        console.clear()
        console.print("[bold blue]Challenge Name?")
        name = input()
        console.clear()
        while (ChallengeManager.check_name_exists(name, type)):
            console.print("Challenge with name already exists", style="bold red")
            console.print("[blue]New challenge Name?")
            name = input()
            console.clear()
        console.print("[bold blue]Challenge Author?")
        author = input()
        console.clear()
        console.print("[bold blue]Challenge Description?")
        description = input()
        console.clear()
        console.print("[bold blue]Challenge Difficulty?")
        console.print("[bold cyan]>[/bold cyan] easy (1)", style="bold green")
        console.print("[bold cyan]>[/bold cyan] easy-medium (2)", style="bold green")
        console.print("[bold cyan]>[/bold cyan] medium (3)", style="bold green")
        console.print("[bold cyan]>[/bold cyan] medium-hard (4)", style="bold green")
        console.print("[bold cyan]>[/bold cyan] hard (5)", style="bold green")
        console.print("[bold cyan]>[/bold cyan] impossible? (6)", style="bold red")
        difficulty = input()
        if difficulty not in ["1", "2", "3", "4", "5", "6"]:
            console.print("Invalid input", style="bold red")
            exit(1)
        if difficulty == "6":
            console.print("You're not that good", style="bold red")
            exit(1)
        if difficulty == "1":
            difficulty = "easy"
        elif difficulty == "2":
            difficulty = "easy-medium"
        elif difficulty == "3":
            difficulty = "medium"
        elif difficulty == "4":
            difficulty = "medium-hard"
        elif difficulty == "5":
            difficulty = "hard"

        console.clear()
        console.print("[bold blue]Challenge Flag?")
        flag = input()
        console.clear()
        console.print("[bold blue]Can your challenge be deployed directly from a docker-compose file? (y/n)")
        deploy = input()
        if deploy not in ["y", "n"]:
            console.print("Invalid input", style="bold red")
            exit(1)
        if type == "1":
            console.print("[bold blue]Use a template? (This does nothing for now, select 3)")
            console.print("[bold cyan]>[/bold cyan] C (1)", style="bold green")
            console.print("[bold cyan]>[/bold cyan] Rust (2)", style="bold green")
            console.print("[bold cyan]>[/bold cyan] No Template (3)", style="green")
            template = input()
            if template not in ["1", "2", "3"]:
                console.print("Invalid input", style="bold red")
                exit(1)
            with console.status("[blue]Building Rev Challenge...", spinner='bouncingBar') as status:
                ChallengeManager.create_rev(name, author, description, difficulty, flag, deploy)
        elif type == "2":
            with console.status("[blue]Building Pwn Challenge...", spinner='bouncingBar') as status:
                ChallengeManager.create_pwn(name, author, description, difficulty, flag, deploy)
        elif type == "3":
            with console.status("[blue]Building Crypto Challenge...", spinner='moon') as status:
                ChallengeManager.create_crypto(name, author, description, difficulty, flag, deploy)
        elif type == "4":
            console.print("[bold blue]Use a template? (This does nothing for now, select 3)")
            console.print("[bold cyan]>[/bold cyan] PHP (1)", style="bold green")
            console.print("[bold cyan]>[/bold cyan] Flask (2)", style="bold green")
            console.print("[bold cyan]>[/bold cyan] No Template (3)", style="green")
            template = input()
            if template not in ["1", "2", "3"]:
                console.print("Invalid input", style="bold red")
                exit(1)
            console.clear()
            with console.status("[blue]Building Web Challenge...", spinner='moon') as status:
                ChallengeManager.create_web(name, author, description, difficulty, flag, deploy)
        elif type == "5":
            with console.status("[blue]Building Misc Challenge...", spinner='bouncingBar') as status:
                ChallengeManager.create_misc(name, author, description, difficulty, flag, deploy)
        elif type == "6":
            with console.status("[blue]Building Blockchain Challenge...", spinner='line') as status:
                ChallengeManager.create_blockchain(name, author, description, difficulty, flag, deploy)
        elif type == "7":
            with console.status("[blue]Building Osint Challenge...", spinner='dots12') as status:
                ChallengeManager.create_osint(name, author, description, difficulty, flag)
        else:
            console.print("What did u do?", style="bold red")
        console.print(f"Run `git checkout -b {author}_{name}` to switch to a branch and please read README.md for the next steps.", style="blue")


        
    else:
        console.print("Invalid input", style="bold red")
