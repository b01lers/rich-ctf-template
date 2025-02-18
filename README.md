# ctf-name-here
Made with the Rich CTF template

### Run mkchal.py

```bash
python3 mkchal/mkchal.py -h
usage: mkchal [-h] --name NAME --desc DESC --author AUTHOR --flag FLAG --type {rev,pwn,crypto,web,misc,blockchain,osint} --deploy {docker,klodd,none}
              [--ports PORTS [PORTS ...]] --autodeploy {False,True} --difficulty {easy,medium,hard,impossible}

Creates a sample challenge for a ctf

options:
  -h, --help            show this help message and exit
  --name NAME           The name of the challenge.
  --desc DESC           The description of the challenge.
  --author AUTHOR       The author of the challenge.
  --flag FLAG           The challenge flag.
  --type {rev,pwn,crypto,web,misc,blockchain,osint}
                        The type of the challenge.
  --deploy {docker,klodd,none}
                        How the challenge will be deployed
  --ports PORTS [PORTS ...]
                        The ports that the challenge provides. Example: 1337 1338
  --autodeploy {False,True}
                        Whether or not the challenge can be automatically deployed.
  --difficulty {easy,medium,hard,impossible}
                        The challenge difficulty.
```

> This will create a new challenge directory with the required files.

### After mkchal.py

- Checkout a new branch 
  - ```bash
    git checkout -b testachall_CygnusX
    ```
- Read the `README.md` inside your created challenge directory

### After verifying your challenge works
 - Push your changes and make a pull request to the ctf repo using the branch given in
 the final output of mkchal.py.
 - Before creating a PR please comment out the ports in your docker-compose file.

## Structure

All challenges can be found in `src`.

Challenges are organized by category into subdirectories:
 - rev
 - crypto
 - pwn
 - misc
 - blockchain
 - osint
 - web

## Directory Structure
```      
challenge_category   
 └── challenge_name         
    ├── deploy             
    │    └──  deployment files              
    ├── dist         
    │    └── files to be given to competitors         
    ├── solve         
    │    └── writeup and solution scripts         
    ├── src         
    │    └── challenge source files         
    ├── chall.json ── challenge information         
    ├── flag.txt ── the flag         
    ├── README.md ── this file         
    └── run.sh ── what will be run to deploy your challenge
```

---

Created by CygnusX and aims to be an improvement on [ctf-template](https://github.com/b01lers/ctf-template) any feedback or suggestions on clarity are welcome.
