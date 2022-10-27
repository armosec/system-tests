REM Setting virtual environment
python -m venv systests_python_env

# systests_python_env\Scripts\activate

systests_python_env\Scripts\pip3 install -r requirements.txt
systests_python_env\Scripts\pip3 install -U casigner --index-url https://cacustomer:x4qfg=4qip1r6t@d@carepo.system.cyberarmorsoft.com/repository/cyberarmor-pypi-dev.group/simple
systests_python_env\Scripts\pip3 install -U cacli --index-url https://cacustomer:x4qfg=4qip1r6t@d@carepo.system.cyberarmorsoft.com/repository/cyberarmor-pypi-dev.group/simple
# deactivate
# $NEXUS3USER:$NEXUS3PASSWORD