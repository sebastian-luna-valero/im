FROM ubuntu:18.04
LABEL maintainer="Miguel Caballer <micafer1@upv.es>"
LABEL version="2.6.20"
LABEL description="Container image to run ansible"


RUN apt-get update && \
    apt install -y --no-install-recommends \
    openssh-client \
    python3-wheel \
    python3-setuptools \
    python3-dev \
    python3-pip \
    python3 \
    git \
    gcc && \
    pip3 install ansible==2.6.20 jmespath scp pywinrm && \
    apt-get purge -y gcc python3-dev python3-pip python3-wheel python3-setuptools && \
    apt autoremove -y && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && rm -rf ~/.cache/

COPY ansible.cfg /etc/ansible/ansible.cfg

CMD ["ansible-playbook"]