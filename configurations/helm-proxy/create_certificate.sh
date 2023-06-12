#!/bin/bash
my_dir=`dirname $0`
# echo $my_dir
# create a self-signed certificate
chmod u+x $my_dir/san_scr.cnf

## generate crt and key
output=$(openssl req -x509 -new -nodes -keyout httpd-proxy.key -out httpd-proxy.crt -config $my_dir/san_scr.cnf -extensions req_ext -days 365 2>&1)

if [ $? -ne 0 ]; then
    echo "failed to get certificates: $?"
    exit $?
fi
echo $output

# delete secrets if exists
kubectl delete secret httpd-proxy-tls
kubectl delete secret apache-certs

# create httpd-proxy-tls secret
output=$(kubectl create secret tls httpd-proxy-tls --cert=httpd-proxy.crt --key=httpd-proxy.key 2>&1)

if [ $? -ne 0 ]; then
    echo "failed to create secret tls httpd-proxy-tls: $output"
    exit $?
fi
echo $output

# create apache-certs secret
output=$(kubectl create secret generic apache-certs --from-file=my-cert.pem=httpd-proxy.crt --from-file=my-key.pem=httpd-proxy.key 2>&1)

if [ $? -ne 0 ]; then
    echo "failed to create secret generic apache-certs: $output"
    exit $?
fi
echo $output


exit 0