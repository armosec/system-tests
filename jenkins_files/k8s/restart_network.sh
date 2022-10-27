#!/bin/bash

set -ex

systemctl stop kubelet
systemctl stop docker
iptables --flush
iptables -tnat --flush
systemctl start kubelet
systemctl start docker
sleep 20
echo "restart coredns pods"
kubectl delete pods -n kube-system $(kubectl get pods -n kube-system | grep coredns | awk '{print $1}')
