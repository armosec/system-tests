#!/bin/bash

echo "user: $USER"
echo "path: $PATH"
python3 --version
pip3 --version
docker --version

#kubectl version --short
#minikube version
#helm version
#go version

echo Setting up python environment \(systests_python_env\)

set -e

LOGFILE=/tmp/last_install_$$.log
SCRIPTPATH="$(
  cd "$(dirname "$0")"
  pwd -P
)"

echo "Path: ${SCRIPTPATH}"

if ! python3 -m venv systests_python_env; then
  echo "Failed to create python environment"
  exit 1
fi

echo "${PWD}"

if [ "$(uname)" == "Darwin" ]; then
  echo "OS: Mac"
  # Needed only on M1 Macs
  # https://github.com/psycopg/psycopg2/issues/1286
  brew install postgresql
  brew install cmake
  brew install openssl
  brew link openssl --force
  source systests_python_env/bin/activate
  LDFLAGS="-L$(brew --prefix openssl@1.1)/lib" CFLAGS="-I$(brew --prefix openssl@1.1)/include" pip3 install -r requirements.txt
  brew unlink openssl
else
  echo "OS: Linux"
  . systests_python_env/bin/activate
  pip3 install -r requirements.txt
  wget https://github.com/Kitware/CMake/releases/download/v3.18.2/cmake-3.18.2-Linux-x86_64.sh -O cmake.sh
  sudo sh cmake.sh --prefix=/usr/local/ --exclude-subdir
fi

rm -rf $LOGFILE 2>/dev/null || true

deactivate

