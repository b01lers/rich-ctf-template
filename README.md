# ctf-name-here
Made with the Rich CTF template

### Run mkchal.py

```bash
$ python3 mkchal/mkchal.py -h

usage: mkchal [-h] --name NAME [--desc DESC] --author AUTHOR [--flag FLAG] --type {rev,pwn,crypto,web,misc,blockchain,osint,jail} --deploy {docker,klodd,none} [--ports PORTS] --autodeploy {False,True}
              --difficulty {easy,medium,hard,impossible} [--build]

Creates a sample challenge for a ctf

options:
  -h, --help            show this help message and exit
  --name NAME           The name of the challenge.
  --desc DESC           The description of the challenge.
  --author AUTHOR       The author of the challenge.
  --flag FLAG           The challenge flag.
  --type {rev,pwn,crypto,web,misc,blockchain,osint,jail}
                        The type of the challenge.
  --deploy {docker,klodd,none}
                        How the challenge will be deployed
  --ports PORTS         The ports that the challenge runs on inside the container.
  --autodeploy {False,True}
                        Whether or not the challenge can be automatically deployed.
  --difficulty {easy,medium,hard,impossible}
                        The challenge difficulty.
  --build               Generate the opt-in container build system for deployed pwn and rev challenges.
```

> This will create a new challenge directory with the required files.

### After mkchal.py

- A sample challenge will be created inside your challenge directory accessible at port 1337.
- Please read the generated README.md in your challenge for more information.
- Checkout a new branch
  - ```bash
    git checkout -b testachall_CygnusX
    ```
- Read the `README.md` inside your created challenge directory
- For deployed pwn/rev challenges generated with `--build`, run `./build.sh` to create `src/chall`.

### After verifying your challenge works
 - Push your changes and make a pull request to the CTF repo.

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
 - jail

## Directory Structure
```
challenge_category
 └── challenge_name
    ├── deploy
    │    └── Klodd deployment files, when applicable
    ├── dist
    │    └── files to be given to competitors
    ├── solve
    │    └── writeup and solution scripts
    ├── src
    │    ├── challenge source files
    │    ├── Dockerfile
    │    └── docker-compose.yml
    ├── build.sh ── optional pwn/rev build script
    ├── chall.json ── challenge information
    ├── README.md ── this file
    └── dev.sh ── what you should use to test your challenge
```

---

Created by CygnusX (with domain specific contributions from Ky28059, Athryx, VinhChilling) and aims to be an improvement on [ctf-template](https://github.com/b01lers/ctf-template) any feedback or suggestions on clarity are welcome.
