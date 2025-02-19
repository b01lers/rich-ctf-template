# Standard debian instance, pin specific version to avoid breaking libc changes and such
FROM debian@sha256:4abf773f2a570e6873259c4e3ba16de6c6268fb571fd46ec80be7c67822823b3 AS {name}_inner_container

# Install any software to run the challenge
# Build tools should be installed in Dockerfile_build

RUN apt-get update && \
apt-get install -y socat

# wrapper.sh wraps the executable by
# performing any necessary setup
# this has to be called /app/run for redpwn jail to work
COPY ./deploy/wrapper.sh /app/run
RUN chmod +x /app/run

# This example copies a prebuild binary into home directory
# The binary can be built by running the ./deploy/build.sh script
COPY ./dist/chall /app/chall
RUN chmod +x /app/chall

# We don't want to forget the flag!
COPY ./flag.txt /app/flag.txt

# this container runs the redpwn jail
FROM pwn.red/jail

# copy challenge container files to /srv
# /srv will be all files in the jail
COPY --from={name}_inner_container / /srv

# redpwn jail options can be found at https://github.com/redpwn/jail?tab=readme-ov-file#configuration-reference
# some example options are set below

# configures allowed memory in redpwn jail
ENV JAIL_MEM=10M
# configures time before chall is killed
ENV JAIL_TIME=120
# use specified port to run challenge
ENV JAIL_PORT={port}
