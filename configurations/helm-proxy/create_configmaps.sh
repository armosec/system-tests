#!/bin/bash
my_dir=`dirname $0`

# delete apache-config configmap if exists
kubectl delete configmap apache-config

# create apache-config configmap
output=$(kubectl create configmap apache-config --from-file=$my_dir/httpd.conf 2>&1)

if [ $? -ne 0 ]; then
    echo "failed to create apache-config configmap: $?"
    exit $?
fi
echo $output

output=$(kubectl apply -f $my_dir/httpd.deploy.yaml 2>&1)

if [ $? -ne 0 ]; then
    echo "failed to deploy httpd-proxy: $?"
    exit $?
fi
echo $output

output=$(kubectl apply -f $my_dir/httpd.svc.yaml 2>&1)

if [ $? -ne 0 ]; then
    echo "failed to deploy httpd-proxy service: $?"
    exit $?
fi
echo $output


output=$(kubectl rollout restart deployment httpd-proxy 2>&1)

if [ $? -ne 0 ]; then
    echo "failed to restart restart deployment httpd-proxy: $?"
    exit $?
fi
echo $output
