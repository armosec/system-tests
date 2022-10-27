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

env_cleanup () {

    echo "***********************************"
    echo " Cleaning up environment"
    echo ""

    sudo -E ${MINIKUBE_BIN} delete --purge --all
}

env_cleanup