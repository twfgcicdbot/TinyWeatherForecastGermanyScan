FROM gitpod/workspace-full:latest

USER gitpod

RUN sudo apt-get update && sudo apt-get upgrade -y
RUN sudo apt-get install -y dexdump
RUN virtualenv env && source env/bin/activate