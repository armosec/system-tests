# Attack Chain #8

<!-- TODO - add image -->

**Initial Access / Cluster Access**

## Steps to reproduce

Create the cluster with **kind** using the provided configuration file:

```shell
kind create cluster --config kind-config --name attack-chains
```

Install **mysql** and **alpine** with their manifests:

```shell
kubectl apply -f 01-exposed-dp.yaml
kubectl apply -f 02-rbac-permissions.yaml
```

## Result

After creating the cluster and installing the manifests you should be able to see attack chain composed like so:

* **Initial Access**: through a `LoadBalancer` service.
* **Cluster Access**: with **alpine** `Deployment` cluster takeover roles.

