
# Just use a standard image
FROM python:3.13-slim-bookworm

# Install any software to build the challenge

RUN apt-get update && \
apt-get install -y socat

# Change example to the name of your challenge.

ENV USER {name}
WORKDIR /home/$USER
RUN useradd $USER

# wrapper.sh wraps the executable by
# `cd`ing to the right place
COPY ./deploy/wrapper.sh /home/$USER/

# This example runs a python script named sample.py
# This works with compiled binaries, just make sure to
# install necessary software and use a Makefile inside the container.
COPY ./src/sample.py /home/$USER/

# We don't want to forget the flag!
COPY ./flag.txt /home/$USER/flag.txt

# Set permissions. Be *VERY* careful
# about changing this!
RUN chown -R root:$USER /home/$USER
RUN chmod -R 550 /home/$USER
RUN chmod -x /home/$USER/flag.txt

# Whatever port you configure in the socat command
EXPOSE {port}

# Serves wrapper.sh which wraps the sample python file
CMD socat TCP-LISTEN:{port},reuseaddr,fork EXEC:"/home/$USER/wrapper.sh"
