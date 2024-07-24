# Attack Chain #9


**unauthnticated serivce**

## Steps to reproduce

Create the cluster with **kind** using the provided configuration file:

```shell
kind create cluster --config kind-config --name attack-chains
```

Create the crd the deployment:

```shell
kubectl apply -f 01-crd.yaml
kubectl apply -f 02-service-unauthnticated.yaml
```

## Result

After creating the cluster and installing the manifests you should be able to see attack chain composed like so:

* **Public facing database without authentication


