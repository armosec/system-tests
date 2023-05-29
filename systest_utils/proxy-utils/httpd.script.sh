# create a self-signed certificate
openssl req -x509 -new -nodes -keyout httpd-proxy.key -out httpd-proxy.crt -config san_scr.cnf -extensions req_ext -days 365
kubectl delete secret httpd-proxy-tls
kubectl create secret tls httpd-proxy-tls --cert=httpd-proxy.crt --key=httpd-proxy.key
# kubectl create secret generic apache-certs --from-file=my-cert.pem=httpd-proxy.crt --from-file=my-key.pem=httpd-proxy.key

# create a configmap from a file
kubectl delete configmap apache-config
kubectl create configmap apache-config --from-file=httpd.conf
kubectl apply -f httpd.deploy.yaml
kubectl apply -f nginx.svc.yaml
kubectl rollout restart deployment httpd-proxy

# test the proxy - for development only
kubectl apply -f ./reg.nginx.yaml
# kubectl exec -it httpd-reg -- bash
# http_proxy=https://httpd-proxy.default curl -vik --proxy-cacert /etc/httpd-proxy/tls/tls.crt https://www.google.com

