#!/bin/bash

set -e

# From minikube howto
export MINIKUBE_WANTUPDATENOTIFICATION=false
export MINIKUBE_WANTREPORTERRORPROMPT=false
export MINIKUBE_HOME=$HOME
export CHANGE_MINIKUBE_NONE_USER=true
export MINIKUBE_IN_STYLE=true
export KUBECONFIG=$HOME/.kube/config

MINIKUBE_BIN=$(which minikube)

check_or_install_minikube() {

    which minikube || {
        echo "Installing minikube"
        wget -q --no-clobber -O minikube
            https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
        chmod +x minikube
        install ./minikube
    }
}


start_minikube() {
    echo "Starting minikube"

    echo ${MINIKUBE_BIN}

    # make sure minikube is not runnig
    ${MINIKUBE_BIN} delete

    # Start minikube
    random_name=$(echo $RANDOM | md5sum | head -c 20)
    ${MINIKUBE_BIN} start -p "$random_name"

#     \
#        --apiserver-ips 127.0.0.1 --apiserver-name localhost \
#        --memory 4096 --cpus 3 --disk-size 20g

    # make sure minikube is configured corsectly and kubectl can work properly
    #sudo mv /root/.kube /root/.minikube $HOME
    #sudo chown -R $USER $HOME/.kube $HOME/.minikube
    minikube -p "$random_name" update-context

    minikube version
    kubectl version --short

    # Wait til minikube ready
    echo "INFO: Waiting for minikube cluster to be ready ..."
    typeset -i cnt=120
    until kubectl --context="$random_name" get pods >& /dev/null; do
        echo "Waiting for minikube cluster to be ready ... # ${cnt}"
        ((cnt=cnt-1)) || exit 1
        sleep 1
    done

}


# Install minikube if missing
check_or_install_minikube

# Start Minikube if not running
start_minikube