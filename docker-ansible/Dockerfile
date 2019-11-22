FROM ubuntu:18.04
LABEL maintainer="Miguel Caballer <micafer1@upv.es>"
LABEL version="2.6.20"
LABEL description="Container image to run ansible"


RUN apt-get update && \
    apt install -y --no-install-recommends \
    openssh-client \
    sshpass \
    sudo \
    python-wheel \
    python-setuptools \
    python-dev \
    python-pip \
    python \
    git \
    gcc && \
    pip install ansible==2.6.20 jmespath scp pywinrm && \
    apt-get purge -y gcc python-dev python-pip python-wheel python-setuptools && \
    apt autoremove -y && \
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && rm -rf ~/.cache/

COPY ansible.cfg /etc/ansible/ansible.cfg

CMD ["ansible-playbook"]