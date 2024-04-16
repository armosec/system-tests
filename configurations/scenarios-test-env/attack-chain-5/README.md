# Attack Chain #5

![attack-chain-5](./ac5.png)

**workload-exposure / vulnerable-image / persistence**

## Steps to reproduce

Create the cluster with **kind** using the provided configuration file:

```shell
kind create cluster --config kind-config --name attack-chains
```

Install **mysql** and **wordpress** with their manifests:

```shell
kubectl apply -f 01-mysql.yaml
kubectl apply -f 02-wordpress.yaml
```

## Result

After creating the cluster and installing the manifests you should be able to see attack chain composed like so:

* **workload-exposure**: through an `Ingress` resource.
* **vulnerable-image**: `wordpress:6.0.1-php7.4` with some critical vulnerabilities, as reported here: [6.0.1-php7.4](https://hub.docker.com/layers/library/wordpress/6.0.1-php7.4/images/sha256-93802164c4fc8e21ef1f48f6ac96e76924aa535d26e1ca67dece41a8b223ca0b?context=explore).
* **persistence**: with `spec.securityContext.readOnlyRootFilesystem` property set to `false` in **wordpress** `Deployment`.

