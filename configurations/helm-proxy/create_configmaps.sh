#!/bin/bash
my_dir=`dirname $0`

# create a configmap from a file
kubectl delete configmap apache-config
kubectl create configmap apache-config --from-file=$my_dir/httpd.conf
kubectl apply -f $my_dir/httpd.deploy.yaml
kubectl apply -f $my_dir/httpd.svc.yaml

# kubectl apply -f $my_dir/nginx.svc.yaml
kubectl rollout restart deployment httpd-proxy
