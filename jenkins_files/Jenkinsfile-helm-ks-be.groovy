def backend = "${env.BACKEND}"
def helm_branch = "${env.HELM_BRANCH}"
def ks_branch = "${env.KS_BRANCH}"

def delete_test_tenant

if (env.DELETE_TEST_TENANT) {
    delete_test_tenant = "${env.DELETE_TEST_TENANT}"
} else {
    delete_test_tenant = "ALWAYS"
}


// Add kubescape-CLI and kubescape-HELM tests that use the BE API
def tests = [
            "ks_microservice_create_2_cronjob_mitre_and_nsa_proxy":                       ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
             "vulnerability_scanning_proxy":                                              ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
             "vulnerability_scanning":                                                    ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
             "vulnerability_scanning_trigger_scan_on_new_image":                          ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
             "ks_microservice_ns_creation":                                               ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
             "ks_microservice_on_demand":                                                 ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
             "ks_microservice_mitre_framework_on_demand":                                 ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
             "ks_microservice_nsa_and_mitre_framework_demand":                            ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
             "ks_microservice_triggering_with_cron_job":                                  ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
             "ks_microservice_update_cronjob_schedule":                                   ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
             "ks_microservice_delete_cronjob":                                            ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
             "ks_microservice_create_2_cronjob_mitre_and_nsa":                            ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
             "scan_with_exceptions":                                                      ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
            //  "scan_security_and_submit_to_backend":                                       ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
             "scan_nsa_and_submit_to_backend":                                            ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
             "scan_mitre_and_submit_to_backend":                                          ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
             "scan_local_repository_and_submit_to_backend":                               ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
             "scan_repository_from_url_and_submit_to_backend":                            ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
             "scan_with_exception_to_backend":                                            ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
             "scan_with_custom_framework":                                                ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
             "scan_customer_configuration":                                               ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
             "scan_compliance_score":                                                     ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
            //  "vulnerability_scanning_cve_exceptions":                                     ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
            // "vulnerability_scanning_trigger_scan_registry_by_backend":                    ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
             "vulnerability_scanning_test_public_registry_connectivity_by_backend" :                       ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
            "vulnerability_scanning_test_public_registry_connectivity_excluded_by_backend":             ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
            "stripe_plans":                    ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
            "stripe_checkout":                 ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
            "stripe_webhook" :                 ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
            "stripe_billing_portal":           ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
            "user_email_settings":             ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"],
            "user_alert_channels":             ["CA-AWS-DEV-JENKINS-EC2-FLEET-X-LARGE",  "k8s"]
             ]


// Define tests to skip. key is environment, value is list of tests to skip
// key can be "production", "staging" or "development"
def tests_to_skip = ["production": 
                            [
                            "stripe_webhook", 
                            "stripe_billing_portal",
                            "user_alert_channels"
                            ]
                    ]

def parallelStagesMap = tests.collectEntries {
    if (tests_to_skip.containsKey("${backend}".toString()) && tests_to_skip["${backend}".toString()].contains(it.key))
        ["${it.key}" : skip_stage(it.value[1], it.key, it.value[0], "${backend}")]
    else 
        ["${it.key}" : generate_stage(it.value[1], it.key, it.value[0], "${backend}", "${delete_test_tenant}")]
}


pipeline {
    agent {
        label 'CA_LINUX_LOCAL_NODE'
    } //agent
    environment {
        BACKEND = "${backend}"
//         SKIP_CLAIR = "true"
    } // environment
    stages {
        stage('Prepare-Tests') {
            steps {
                stash includes: '**', name: 'test-workspace'
            } //steps
        } //stage
        stage('Run-system-tests') {
           steps {
                script{
                    try {
                            parallel parallelStagesMap
                    } catch (err){
                        echo "${err}"
                        currentBuild.result = 'FAILURE'
                    } finally {
                        echo "finally"
                    }
                } //script
           } // steps
        } //stage('Run-tests')
    } //stages
} //pipeline


def skip_stage(platform, test, run_node, backend){
        return {
            stage("${test} (skipped)") {
                echo "skipping test '${test}' for environment '${backend}'"
            } //stage
        }
    }


def generate_stage(platform, test, run_node, backend, delete_test_tenant){
    if ("${platform}" == 'k8s'){
        return {
            stage("${test}") {
                node("${run_node}"){
                    env.CA_IGNORE_VERIFY_CACLI = "true"
                    unstash 'test-workspace'
                    print_hostname()
                    try {
                        clean_docker_history()
                        start_minikube()
                        prep_test()
                        run_test("${test}", "${backend}", "${ks_branch}", "${helm_branch}", "${delete_test_tenant}")
                    } catch (err){
                        echo "${err}"
                        currentBuild.result = 'FAILURE'
                    } finally {
                        echo "finally"
                        remove_minikube()
                        clean_docker_history()
                        cleanWs()
                    }
                } //node
            } //stage
        }
    }
}


def start_minikube(){
	script{
		sh '''
	    #!/bin/bash
        ./jenkins_files/k8s/start_profiled_minikube.sh
	    '''
	} //script
}

def remove_minikube(){
	script{
		sh '''
	    #!/bin/bash
        ./jenkins_files/k8s/remove_minikube.sh
	    '''
	} //script
}


def checkout_sources() {
    checkout(
        [
        $class: 'GitSCM',
        branches:[[name: '*/master']],
        userRemoteConfigs:[[credentialsId: 'd20e86b7-33c4-40b8-8416-43ac83dec40d',
                            url: 'git@10.42.4.1:cyberarmor/systests.git']]
        ]
        )
}

def prep_test(){
    script{
        sh '''
        #!/bin/bash
        ./create_env.sh
        '''
    } //script
}

def clean_docker_history(){
    script{
        sh '''
        #!/bin/bash
        docker rm -fv $(docker ps -aq) || true
        docker image rm -f $(docker images) || true
        docker system prune -f || true
        docker image prune -f || true
        '''
    } //script
}

def run_test(String test_name, String backend, String ks_branch, String helm_branch, String delete_test_tenant){
    try {
        withCredentials([string(credentialsId: 'customer-for-credentials', variable: 'CUSTOMER'), string(credentialsId: 'name-for-credentials', variable: 'USERNAME'), string(credentialsId: 'password-for-credentials', variable: 'PASSWORD'), string(credentialsId: 'client-id-for-credentials-on-'+"${env.BACKEND}", variable: 'CLIENT_ID'), string(credentialsId: 'secret-key-for-credentials-on-'+"${env.BACKEND}", variable: 'SECRET_KEY'), string(credentialsId: 'REGISTRY_USERNAME', variable: 'REGISTRY_USERNAME'), string(credentialsId: 'REGISTRY_PASSWORD', variable: 'REGISTRY_PASSWORD')]) {
            sh '''
            #!/bin/bash
            echo "Test history:"
            echo "''' + test_name + ''';;" >>/tmp/testhistory
            cat /tmp/testhistory
            source systests_python_env/bin/activate
            python3 systest-cli.py -t ''' + test_name + ''' -b ''' + backend + ''' -c CyberArmorTests --logger DEBUG --delete_test_tenant '''+ delete_test_tenant +''' --kwargs ks_branch=''' + ks_branch +'''  helm_branch='''+helm_branch+'''
            deactivate
            '''
        }
    } catch (err) {
        echo "${err}"
        currentBuild.result = 'FAILURE'
    } finally {
        try {
            junit "**/${test_name}.xml"
        } catch (err) {
            echo "${err}"
        }
    }
}

def send_email(){
    emailext body: "${env.JOB_NAME} build ${env.BUILD_NUMBER}\n <br> More info at: ${env.BUILD_URL}<br>Blue Ocean: ${env.RUN_DISPLAY_URL}\n<br>\n\n${currentBuild.rawBuild.getLog(300).join('\n<br>')} <br><br>\n\n${testOutput}\n\n",
            subject: "Test failed (${env.JOB_NAME} build ${env.BUILD_NUMBER})",
            to: 'development@cyberarmor.io'

}

def send_email_success(){
    println 'Build status: ' + currentBuild.result
    if(currentBuild.result == null || currentBuild.result == 'SUCCESS'){
        emailext body: "<h1><font color=\"green\">SUCCESS!!!</font></h1>\n<br>${env.JOB_NAME} build ${env.BUILD_NUMBER}\n <br> More info at: ${env.BUILD_URL}<br>\n<br>Blue Ocean: ${env.RUN_DISPLAY_URL}<br><br>\n",
        subject: "K8S Systest SUCCESS!!! (${env.JOB_NAME} build ${env.BUILD_NUMBER})",
        to: 'development@cyberarmor.io'
    }
}

def print_hostname(){
    sh '''
    #!/bin/bash
    echo $HOSTNAME
    echo "IP:"
    curl http://169.254.169.254/latest/meta-data/public-ipv4
    '''
}
