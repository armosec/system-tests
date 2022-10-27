# SystemTests Development

## Setup locally

1. Clone systests repo
    ```sh
   git clone git@github.com:armosec/systests.git
   ```
2. Create virtual env
   ```sh
   ./create_env.sh
   ```
3. Activate virtual env
   ```sh
   source systests_python_env/bin/activate
   ```
4. Run profiled minikube (in case you do not have a kubernetes cluster)
   1. Start minikube
      ```sh
        minikube start -p <minikube-name>
      ```
   2. Update `~/.bashrc`/`~/.zprofile` file
      ```sh
      eval $(minikube -p <minikube-name> docker-env)
      ```
5. Execute systemtest command
    ```sh
   python systest-cli.py -t <test name> -b production -c CyberArmorTest
   ```
   > In case of helm/KS testing, it is recommended to cleanup your local environment before running the test
   > * Cleanup kubescape local environment: ```kubescape config delete```
   > * Cleanup helm local environment: ```helm uninstall armo -n kubescape```

### Examples

#### List test names
```sh
python systest-cli.py --list t
```

#### Run test against ARMO production BE
```sh
python systest-cli.py -t <test name> -b production -c CyberArmorTest
```

#### Run test against ARMO development BE
```sh
python systest-cli.py -t <test name> -b development -c CyberArmorTest
```

#### Run test using kubescape dev branch & helm dev branch against ARMO production BE
```sh
python systest-cli.py -t <test name> -b production -c CyberArmorTest --kwargs ks_branch=dev helm_branch=dev
```

## Add new test

### Write a new test

// TODO

### Check your test before adding it to the pipeline
Before adding a test to the Jenkinsfiles pipeline, please make sure the test passes locally and in the Jenkins environment

1. Duplicate the `CAA_Single_System_Tests` Jenkinsjob and name it `CAA_Single_System_Tests_<My_Bramch>`
2. Edit the branch name

![img_1.png](jenkins_files/img_1.png)

### Add new test to the pipelines

After your test passed in single test, you can add it to the pipeline.

There are three components we test:
* Armo BE
* Helm chart
* Kubescape

For this we have three different Jenkinsfiles:
* Armo BE - `Jenkinsfile-helm-ks-be.groovy`
* Helm chart - `Jenkinsfile_helm_chart.groovy`
* Kubescape - `Jenkinsfile_kubescape.groovy`

Make sure to update the relevant file/s once you complete developing your test
