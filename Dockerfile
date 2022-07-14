# syntax=docker/dockerfile:1

#FROM python:latest
FROM ubuntu:20.04 

WORKDIR /autosec

COPY requirements.txt requirements.txt

COPY autosec/test/endpoints_sim.py endpoints_sim.py


RUN set -xe \
    && apt-get update -y \
    && apt-get upgrade -y \
    && apt-get install -y python3-pip \
    && apt-get install kmod -y

#RUN pip install --upgrade pip
RUN pip3 install -r requirements.txt

# load vcan kernel module, create vcan interface, get vcan interface online
RUN sudo modprobe vcan            
RUN ip link add name vcan0 type vcan
RUN ip link set dev vcan0 up

CMD ["python3", "endpoints_sim.py"]
