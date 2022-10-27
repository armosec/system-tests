set PYTHON_ENV_DIR=python_virtual_env

REM if exist "%PYTHON_ENV_DIR%" (
REM 	echo "virtualenv already in place"
REM ) else (
python -m venv %PYTHON_ENV_DIR% || goto :error
REM )

echo "Entering python virtual environment"
call %PYTHON_ENV_DIR%\Scripts\activate || goto :error

echo "Installing TestRunner requirments..."
pip install docker junit_xml bs4 python-keycloak pymongo requests elasticsearch==6.0.0 pymysql pefile pyelftools python-dateutil redis boto3 hdfs psycopg2-binary oauthlib requests_oauthlib humanfriendly scapy==2.4.0 python-wordpress-xmlrpc mechanize progress colorama cryptography urllib3

echo "Running TestRunner CLI"

python cli.py %* || goto :error

if %ERRORLEVEL% EQU 1 (
    echo Test failed %errorlevel%!
    echo "Exiting python virtual environment"
    deactivate.bat
    exit 1
)
if %ERRORLEVEL% EQU 0 (
    echo Tests succeeded!
    echo "Exiting python virtual environment"
    deactivate.bat
    exit 0
)


:error
set errorlevelAB=%errorlevel%
echo Failed with error #%errorlevelAB%.
deactivate.bat
exit %errorlevelAB%