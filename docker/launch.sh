#!/bin/bash

RAND_PASS=$(openssl rand -hex 16)
SSH_PASSWORD=${1:-${RAND_PASS}}

useradd ${SSH_USERNAME}
echo "${SSH_USERNAME}:${SSH_PASSWORD}" | chpasswd

service ssh start

export SSH_USERNAME
export SSH_PASSWORD

im_service.py