#!/bin/bash

PWD_DIR=${PWD}
FILE_DIR="$( cd "$(dirname "$0")" ; pwd -P )"

if [ "${FILE_DIR}" != "${PWD_DIR}" ]; then

    echo "Changing to $FILE_DIR"
    cd "${FILE_DIR}"
fi


if [ ! -d "python_virtual_env" ]; then

    python3.6 -m venv python_virtual_env

fi

echo "Entering python virtual environment"
source python_virtual_env/bin/activate

echo "Installing TestRunner requirments..."
pip3 install -r requirements.txt

# Run the tests
python3.6 cli.py "$@" 
echo "Exiting python virtual environment"
deactivate

if [ "${FILE_DIR}" != "${PWD_DIR}" ]; then

    echo "Returning to $PWD_DIR"
    cd "${PWD_DIR}"
fi
