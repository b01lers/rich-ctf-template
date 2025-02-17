# ctf-name-here
New age CTF Template (WIP)

## Setup

### Install the reuqired packages

```bash
pip install -r requirements.txt
```

### Run mkchal.py

```bash
python3 mkchal/mkchal.py
```

> This will create a new challenge directory with the required files.

### After mkchal.py

- Run `git checkout -b name_challname` to switch to a branch if you havent already.
- Put your challenge files in `[challname]/src`
- Put your writeup in `[challname]/README.md`
- Put your files that will be given to others in `[challname]/dist`
- Modify the `[challname]/deploy/Dockerfile` file to your needs
- Modify the `[challname]/deploy/docker-compose.yml` file to your needs
- Modify the `[challname]/run.sh` file to however your challenge will be deployed.

### After verifying your challenge works
 - Push your changes and make a pull request to the ctf repo using the branch given in
 the final output of mkchal.py

