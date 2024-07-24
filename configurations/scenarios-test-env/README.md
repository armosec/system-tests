# Attack Chains Test Env

This is a collection of vulnerable scenarios for the **attack chains** feature.

* [attack-chain-1.1](./attack-chain-1.1/)
* [attack-chain-1.2](./attack-chain-1.2/)
* [attack-chain-2](./attack-chain-2/)
* [attack-chain-3](./attack-chain-3/)
* [attack-chain-4](./attack-chain-4/)
* [attack-chain-5](./attack-chain-5/)
* [attack-chain-6](./attack-chain-6/)
* [attack-chain-7](./attack-chain-7/)
* [attack-chain-8](./attack-chain-8/)
* [attack-chain-9](./attack-chain-9/)

## Requirements

Altough all the tests have been performed on a Linux system, there are no OS limitations to run attack chain scenarios, since they depends on **kubernetes**. Ensure to have installed the following tools in your OS in order to be able to setup and interact with the cluster:

* [`kind`](https://github.com/kubernetes-sigs/kind/#installation-and-usage)
* [`kubectl`](https://kubernetes.io/docs/tasks/tools/#kubectl)

If you want to run the script `deploy_scenario` to speed up the scenarios installation, ensure to have a `bash` shell on your system.

## Setup

To setup the wanted scenario that you want to test, please follow the instructions below:

### Create local cluster with `kind`

Each scenario directory has its own `kind-config` file. This is used to create the right environment.

Suppose you want to setup the environment for scenario [#7](./attack-chain-7/):

```shell
kind create cluster --config attack-chain-7/kind-config --name attack-chain-7
```

### Deploy the scenario

Use this command to deploy the scenario manifests in your cluster:

```shell
./deploy_scenario attack-chain-7
```

### Delete the cluster

Once you finished testing the given scenario, you can remove it with the following command:

```shell
kind delete cluster --name attack-chain-7
```
