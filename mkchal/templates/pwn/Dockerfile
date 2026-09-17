# Pin the base used by both the runtime and optional Dockerfile_build.
FROM --platform=linux/amd64 debian@sha256:4abf773f2a570e6873259c4e3ba16de6c6268fb571fd46ec80be7c67822823b3 AS base

WORKDIR /app

FROM base AS safe_{name}_inner_container

# redpwn jail executes /app/run. Build it explicitly with ./build.sh,
# or provide your own chall file before building the runtime image.
COPY chall /app/run
COPY flag.txt /app/flag.txt
RUN chmod 555 /app/run && chmod 444 /app/flag.txt

# this container runs the redpwn jail
FROM pwn.red/jail
WORKDIR /app

# copy challenge container files to /srv
# /srv will be all files in the jail
COPY --from=safe_{name}_inner_container / /srv

# redpwn jail options can be found at https://github.com/redpwn/jail?tab=readme-ov-file#configuration-reference
# some example options are set below

# configures allowed memory in redpwn jail
ENV JAIL_MEM=10M
# configures time before chall is killed
ENV JAIL_TIME=120
# use specified port to run challenge
ENV JAIL_PORT={port}
