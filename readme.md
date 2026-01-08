# CYBER-ARMOR SYSTEM TESTS
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Farmosec%2Fsystem-tests.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Farmosec%2Fsystem-tests?ref=badge_shield)

---

### Important Notice for Test Creation

When adding new tests, it is crucial to include them in the `system_test_mapping.json` file. Failing to do so will result in the tests not being executed. Please ensure to specify the following parameters for each test:

- `target`: This parameter defines the context in which the test will run. The available options are:
  - **CLI**
  - **Backend**
  - **In cluster**

- `target_repositories`: Specify the repository or repositories where the test should be executed. The options include:
  - `cadashboardbe`
  - `event-receiver`
  - `event-ingester-service`
  - `config-service`
  - `gateway`

- `skip_on_environment`: Use this parameter if the test should not be executed in a specific environment. The environments can be:
  - **Production**
  - **Staging**
  - **Development**

- `description`: Provide a brief yet comprehensive description of the test.

Please ensure all these details are accurately filled to maintain the effectiveness and organization of our testing process.

## Test Cases:
| Test name                                                      |  category  | description                                                            | coverage                      |
|----------------------------------------------------------------|:----------:|------------------------------------------------------------------------|-------------------------------|
| `scan_security`                                                | kubescape, security  | simple scan framework security                                              | kubescape                     |
| `scan_nsa`                                                     | kubescape  | simple scan framework NSA                                              | kubescape                     |
| `scan_mitre`                                                   | kubescape  | simple scan framework MITRE                                            | kubescape                     |
| `scan_with_exceptions`                                         | kubescape  | scan framework NSA with exceptions                                     | kubescape                     |
| `scan_repository`                                              | kubescape  | scan repository                                                        | kubescape                     |
| `scan_local_file`                                              | kubescape  | scan local file                                                        | kubescape                     |
| `scan_local_glob_files`                                        | kubescape  | scan local glob files                                                  | kubescape                     |
| `scan_local_list_of_files`                                     | kubescape  | scan local list of files                                               | kubescape      
| `scan_nsa_and_submit_to_backend`                               | kubescape  | scan framework NSA and test results against the backend                | kubescape, backend            | 
| `scan_git_repository_and_submit_to_backend`               | kubescape  | scan git repository and test results against the backend          | kubescape, backend            |
| `scan_with_exception_to_backend`                               | kubescape  | scan framework NSA with exception and test results against the backend | kubescape, backend            | 
| `scan_with_custom_framework`                                   | kubescape  | scan custom framework and test results against the backend             | kubescape, backend            |
| `scan_compliance_score`                                        | kubescape  | scan and test compliance score from kubescape report and from backend  | kubescape, backend            |
| `scan_customer_configuration`                                  | kubescape  | scan controls with customer configuration                              | kubescape, backend            |
| `host_scanner`                                                 | kubescape  | scan with host scanner                                                 | kubescape                     |
| `host_scanner_with_hostsensorrule`                             | kubescape  | scan with host scanner using rules with `hostSensorRule: true`         | kubescape                     |
| `vuln_scan`                                       | helm-chart |                                                                        | kubevuln, backend             |
| `vuln_scan_proxy`                                       | helm-chart |                                                                        | kubevuln, backend             |
| `vuln_v2_views`                                       | helm-chart |                                                                        | kubevuln, backend             |
| `vuln_v2_views`                                       | helm-chart |                                                                        | kubevuln, backend             |
| `ks_microservice_ns_creation`                                  | helm-chart |                                                                        | in-cluster kubescape, backend |
| `ks_microservice_on_demand`                                    | helm-chart |                                                                        | in-cluster kubescape, backend |
| `ks_microservice_mitre_framework_on_demand`                    | helm-chart |                                                                        | in-cluster kubescape, backend |
| `ks_microservice_nsa_and_mitre_framework_demand`               | helm-chart |                                                                        | in-cluster kubescape, backend |
| `ks_microservice_triggering_with_cron_job`                     | helm-chart |                                                                        | in-cluster kubescape, backend |
| `ks_microservice_update_cronjob_schedule`                      | helm-chart |                                                                        | in-cluster kubescape, backend |
| `ks_microservice_delete_cronjob`                               | helm-chart |                                                                        | in-cluster kubescape, backend |
| `ks_microservice_create_2_cronjob_mitre_and_nsa`               | helm-chart |                                                                        | in-cluster kubescape, backend |
| `attackchains_all`                | helm-chart |                                    | in-cluster kubescape, backend |
| `ks_microservice_create_2_cronjob_mitre_and_nsa_proxy`               | helm-chart |                                                                        | in-cluster kubescape, backend |
| `vuln_scan_triggering_with_cron_job`              | helm-chart |                                                                        | kubevuln, backend             |   |
| `stripe_checkout`                                              | payment |                                                                           | stripe, backend             |
| `stripe_billing_portal`                                        | payment |                                                                           | stripe, backend             |
| `stripe_plans`                                                 | payment |                                                                           | stripe, backend             |
| `stripe_webhook`                                               | payment |                                                                           | stripe, backend             |
| `user_email_settings`                                          | users-notification |                                                                | notifications, backend             |
| `user_alert_channels`                                          | users-notification |                                                                | notifications, backend             |
| `synchronizer`                      | helm-chart |  synchronizer happy flow    | in-cluster synchronizer, backend |
| `synchronizer_reconciliation`       | helm-chart |  synchronizer reconciliation flow | in-cluster synchronizer, backend |
| `synchronizer_proxy`                | helm-chart |  synchronizer network disconnection and proxy | in-cluster synchronizer, backend |
| `sr_r_0035_attack_chain`             | helm-chart |                                    | in-cluster kubescape, backend |
| `sr_r_0005_control`             | helm-chart |                                    | in-cluster kubescape, backend |
| `sr_r_0007_control_networkpolicy`             | helm-chart |                                    | in-cluster kubescape, backend |
| `sr_with_exceptions`             | helm-chart |                                    | in-cluster kubescape, backend |
| `basic_incident_presented`         | helm-chart |  basic incident from in cluster presented in BE API | in-cluster , backend |
| `smart_remediation_all_controls` | helm-chart | Test all smart remediation controls | in-cluster , backend |
| `kdr_runtime_policies_configurations`  | helm-chart | Test runtime policy configurations - list, create, update, delete, unique values | in-cluster, backend |

### Install:
* download/clone repository
* create a python environment 
    ```
    ./create_env.sh
    ```

### Run:
#### preparation:
Add to environment the following values to connect to the backend:  

| Argument name       | Description                         | Required for                                                       |
|:--------------------|-------------------------------------|--------------------------------------------------------------------|
| `CUSTOMER`          | customer name for login to keycloak | for all tests                                                      |
| `USERNAME`              | username for login to keycloak      | for all tests                                                      |
| `PASSWORD`          | password for login to keycloak      | for all tests                                                      |
| `CLIENT_ID`         | part of api-token                   | for scan_image_controls test                                       |
| `SECRET_KEY`        | part of api-token                   | for scan_image_controls test                                       |
| `registry_username` |                                     | for vuln_scan_trigger_scan_private_quay_registry test |
| `registry_password` |                                     | for vuln_scan_trigger_scan_private_quay_registry test |


#### Run Arguments:

| Command                                | Description                                                                                                                            | options                                | required/default |
|:---------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|:---------------------------------------|:----------------:|
| `--list`                               | Display lists of configured tests, backends and customers                                                                              | 
| `-t`/ `--test`                         | test name as configured in test file configuration                                                                                     | mysql/apache etc.                      |     requared     |
| `-b`/ `--backend`                      | cyberArmor backend                                                                                                                     | development/staging/production         |   development    |
| `-c`/ `--customer`                     | cyberArmor customer as configured in csutomer file                                                                                     |                                        | CyberArmorTests  |
| `-f`                                   | use docker images from the past, build new ones (and remove the old ones)                                                              |                                        |       True       |
| `-agent`/ `--override-agent`           | Use local agent                                                                                                                        | -agent /local/agent/location/libcaa.so |       None       |
| `-g`/ `--gradual`                      | Run agent in gradual mode                                                                                                              |                                        |      False       |
| `--skip_signing`                       | skip signing on container/files                                                                                                        |                                        |      False       |
| `-d`/ `--duration`                     | test duration- time for the test                                                                                                       |                                        |    3 minutes     |
| `--ignore_agent_errors`                | test will not fail because errors reported by the agent, *all* errors will be ignored. recommended when the `skip_signing` flag is set |                                        |      False       |
| `--run_without_agent`                  | run test without loading agent                                                                                                         |                                        |      False       |
| `--force-remove-container`             | if container with same name is running then remove the running container                                                               |                                        |      False       |
| `-temp`/ `--temp-dir`                  | temp dir location, make sure the test has r/w privileges                                                                               |                                        |      ./temp      |
| `-lcn`/ `--leave-cyberarmor-namespace` | Leave CyberArmor namespace after test is done                                                                                          |                                        |      False       |
| -h                                     | Help                                                                                                                                   | 
| `--delete_test_tenant` | When to delete test tenant, if configured for test                                                                                          |  ALWAYS(default), TEST_PASSED, NEVER                                       |      False       |




#### kwargs options

| Command                  | Description                                                                                  |
|:-------------------------|----------------------------------------------------------------------------------------------|
| `ks_branch=value`        | install kubescape from branch value                                                          |
| `helm_branch=value`      | install helm-chart from branch value                                                         |
| `local_helm_chart=value` | local repo to install the helm-chart                                                         |
| `charts_name=value`      | chart directory name to use from the cloned repo (e.g., kubescape-operator, rapid7-operator) |
| `charts_repo=value`      | repo to clone for the chart (e.g., kubescape/helm-charts, armosec/helm-charts)               |
| `kubescape=value`        | use local kubescape in located in path: value                                                |
| `kubescape-tag=value`    | install helm-chart with kubescape from tag: value                                            |
| `kubevuln-tag=value`     | install helm-chart with kubevuln from tag: value                                             |
| `operator-tag=value`     | install helm-chart with operator from tag: value                                             |
| `kollector-tag=value`    | install helm-chart with kollector from tag: value                                            |
| `gateway-tag=value`      | install helm-chart with gateway from tag: value                                              |


#### Run command:


Activate virtual environment 
```
. systests_python_env/bin/activate
```

Run test with desired options/flags
```
./python3 systest-cli.py -t <test-name> -b <backend> -c <customer>
```


Deactivate environment
```
deactivate
```



## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Farmosec%2Fsystem-tests.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Farmosec%2Fsystem-tests?ref=badge_large)
