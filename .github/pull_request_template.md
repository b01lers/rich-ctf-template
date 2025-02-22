Checklist For PRs:

- [ ] Ports have been commented out in your `docker-compose.yml` if applicable.
 ```yml
 ports:
  - 1337
 ```
 becomes
 ```yml
 # ports:
 # - 1337
 ```
- [ ] Traefik network has been uncommented in your `docker-compose.yml` if applicable.
 ```yml
     # external: true  
 ```
 becomes
 ```yml
    external: true 
 ``` 
- [ ] Is solvable (you don't have to solve it blind, just go through the solve and validate it and sanity check it)
- [ ] Flag is in `bctf{...}` format (if impossible, the format is noted in the description.)
- [ ] Writeup is present in `solve/README.md`
- [ ] Writeup is high quality and completely explains how to solve the challenge from scratch
- [ ] `chal.json` is present in the challenge root directory and contains:
  - [ ] Challenge Title
  - [ ] Challenge Author
  - [ ] Challenge Difficulty `[Easy, Medium, Hard]`
  - [ ] Challenge Description (for distribution, this is your flavor text)
- [ ] Local build files are present in `./src` if applicable (Makefile etc)
- [ ] Remote deployment files are present in `./deploy` if applicable.
  - [ ] Dockerfile
  - [ ] docker-compose.yml
  - [ ] run.sh
  - [ ] challenge.yml