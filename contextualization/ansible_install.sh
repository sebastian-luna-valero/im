#!/bin/sh

distribution_id() {
    RETVAL=""
    if [ -z "${RETVAL}" -a -e "/etc/os-release" ]; then
        . /etc/os-release
        RETVAL="${ID}"
    fi

    if [ -z "${RETVAL}" -a -e "/etc/centos-release" ]; then
        RETVAL="centos"
    fi

    if [ -z "${RETVAL}" -a -e "/etc/fedora-release" ]; then
        RETVAL="fedora"
    fi

    if [ -z "${RETVAL}" -a -e "/etc/redhat-release" ]; then
        RELEASE_OUT=$(head -n1 /etc/redhat-release)
        case "${RELEASE_OUT}" in
            Red\ Hat\ Enterprise\ Linux*)
                RETVAL="rhel"
                ;;
            CentOS*)
                RETVAL="centos"
                ;;
            Fedora*)
                RETVAL="fedora"
                ;;
        esac
    fi

    if [ -z "${RETVAL}" ]; then
        RETVAL="unknown"
    fi

    echo ${RETVAL}
}

distribution_major_version() {
	if [ -f /etc/lsb-release ]; then
		. /etc/lsb-release
		echo ${DISTRIB_RELEASE} | sed -e 's|\([0-9]\+\)\([0-9.]*\).*|\1|'
	else
	    for RELEASE_FILE in /etc/system-release \
	                        /etc/centos-release \
	                        /etc/fedora-release \
	                        /etc/redhat-release
	    do
	        if [ -e "${RELEASE_FILE}" ]; then
	            RELEASE_VERSION=$(head -n1 ${RELEASE_FILE})
	            break
	        fi
	    done
	    echo ${RELEASE_VERSION} | sed -e 's|\(.\+\) release \([0-9]\+\)\([0-9.]*\).*|\2|'
	fi
}

if [ $(which ansible-playbook) ]; then
    echo "Ansible installed. Do not install."
else
    echo "Ansible not installed. Installing ..."
    DISTRO=$(distribution_id)
    case $DISTRO in
        debian)
            apt-get update
            apt-get -y curl
            ;;
        ubuntu)
            apt-get update
            apt-get -y curl
            ;;
        rhel)
            yum install -y curl
            ;;
        centos)
            yum install -y epel-release curl
            ;;
        fedora)
            yum install -y curl yum
            ;;
    	*)
            echo "Unsupported distribution: $DISTRO"
            ;;
    esac

  ANSIBLE_VERSION=devel2
  ANSIBLE_IMAGE=grycap/ansible

  ls /usr/local/bin/udocker || curl https://raw.githubusercontent.com/indigo-dc/udocker/master/udocker.py > /usr/local/bin/udocker
  chmod u+rx /usr/local/bin/udocker
  ls $HOME/.udocker || udocker --allow-root install
  ls $HOME/.udocker/repos/$ANSIBLE_IMAGE/$ANSIBLE_VERSION || udocker --allow-root pull $ANSIBLE_IMAGE:$ANSIBLE_VERSION
  ls $HOME/.udocker/containers/ansible || udocker --allow-root create --name=ansible $ANSIBLE_IMAGE:$ANSIBLE_VERSION

fi

if [ $(udocker --allow-root run ansible which ansible) ]; then
	echo '{"OK" : true}' > $1
else
	echo '{"OK" : false}' > $1
fi

chmod 666 $1