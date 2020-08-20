FROM debian:buster

RUN apt-get update
RUN apt-get upgrade

# Install tools
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential net-tools procps curl wget file netcat vim

# Plant command in docker history
RUN echo "You found the docker history! If this was a ctf you would get a DVDC{FLAG}"

# Set entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]

# Create privesc vector in case of gid mismatch
RUN chmod 4000 /usr/sbin/groupadd
RUN groupadd giddy

# Create a low privileged user
RUN useradd -ms /bin/bash user
RUN usermod -a -G users user
RUN usermod -a -G giddy user
USER user
WORKDIR /home/user
