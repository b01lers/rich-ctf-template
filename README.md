# ctf-template2
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

- Put your challenge files in `[challname]/src`
- Put your writeup in `[challname]/README.md`
- Put your files that will be given to others in `[challname]/dist`
- Modify the `[challname]/deploy/Dockerfile` file to your needs
- Modify the `[challname]/deploy/docker-compose.yml` file to your needs
- Modify the `[challname]/run.sh` file to however your challenge will be deployed.
- A fake flag has been generated in `dist/flag.txt`, move it to where the flag would be, or delete it if the flag is not necessary in dist.

