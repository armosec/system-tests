#!/bin/bash

set -e

# From minikube howto
export MINIKUBE_WANTUPDATENOTIFICATION=false
export MINIKUBE_WANTREPORTERRORPROMPT=false

LOGS_DIR=tester_logs
RESULTS_SUMMARY_FILE=test_results_summary.txt

analyze_logs () {

    echo "***********************************"
    echo " Analyzing Jmeter Logs"
    echo "***********************************"
    echo ""

    cat /dev/null > ${RESULTS_SUMMARY_FILE}

    for filename in `ls ${LOGS_DIR}/*.jtl`; do
        [ -e "$filename" ] || continue

        name=${filename##*/}
        #echo " Analyzing $name file"

        total_number_of_requests=`tail -n +2 ${filename} | wc -l`
        total_number_of_success_requests=`tail -n +2 ${filename} | awk -F ',' '{print$8}' | grep 'true' | wc -l`

        echo " In $name there are ${total_number_of_success_requests} success requests out of ${total_number_of_requests} total request"
        echo ""

        echo "${name},${total_number_of_requests},${total_number_of_success_requests}" >> ${RESULTS_SUMMARY_FILE}
    done

}

analyze_logs