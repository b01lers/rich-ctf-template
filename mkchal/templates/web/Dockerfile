
# Just use a standard image
FROM python:3.13-slim-bookworm

# Install any software to build the challenge here:

RUN python3 -m pip install Flask

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

# Whatever port you configure in your web server
# PROBABLY this should stay 1337. Just change
# The passthrough port in docker-compose.yml below.
EXPOSE 1337

# Serves wrapper.sh which wraps the sample python file
CMD "/home/$USER/wrapper.sh"