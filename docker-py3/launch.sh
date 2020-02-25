#!/bin/bash

useradd ${SSH_USERNAME}
echo "${SSH_USERNAME}:${SSH_PASSWORD}" | chpasswd

service ssh start

export SSH_USERNAME
export SSH_PASSWORD

im_service.py