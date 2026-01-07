import os.path
import sys
import subprocess
import time

tests = [
    "scan_nsa",
    "scan_mitre",
    "scan_with_exceptions",
    "scan_repository",
    "scan_local_file",
    "scan_local_glob_files",
    "scan_local_list_of_files",
    "scan_nsa_and_submit_to_backend",
    "scan_git_repository_and_submit_to_backend",
    "scan_with_exception_to_backend",
    "scan_with_custom_framework",
    "scan_with_kubescape_helm_chart",
    "scan_image_controls",
    "scan_compliance_score"
]

sep = "=" * 40


def get_args():
    if len(sys.argv) < 3:
        print("This script should receive at last 2 argument.\n"
              "1. kubescape-exec: path to local kubescape execution.\n"
              "2. backend-environment: At last one from dev/development, prod/production, stage/staging")
        return "ERROR", None, None

    kubescape_exec = sys.argv[1]
    if not os.path.exists(kubescape_exec) or not os.path.isfile(kubescape_exec):
        print("ERROR: path to kubescape-exec is incorrect")
        return "ERROR", None, None

    environments = []
    for i in range(2, len(sys.argv)):
        environment = sys.argv[i]
        if environment == 'prod':
            environment = 'production'
        if environment == 'dev':
            environment = 'development'
        if environment == 'stage':
            environment = 'staging'

        if environment != 'development' and environment != 'production' and environment != 'staging':
            print(f'incorrect argument to environment: "{environment}", should be production or development or staging')
            return "ERROR", None, None

        environments.append(environment)

    return None, kubescape_exec, environments


def print_summery(summery_test: dict, environment: str):
    print(f"\n\n{sep}\nsummery: {environment}\n\n")
    for i, j in enumerate(summery_test.items()):
        print(f"{i+1}. {j[0]}: {j[1]}")


def run_all_tests(kubescape_exec: str, environment: str):
    summery_test = {}
    passed = True
    for i, test_name in enumerate(tests):
        print(f"\n\n{sep} Test: {test_name} {sep}\n")
        try:
            os.system(f"{kubescape_exec} config delete")
        except:
            pass

        try:
            cmd = f'python3 systest-cli.py -t {test_name} -b {environment} -c CyberArmorTests --kwargs kubescape={kubescape_exec}'
            result = subprocess.run(cmd.split(" "), timeout=1000)
            if result.returncode != 0:
                summery_test[test_name] = 'failed'
                passed = False
            else:
                summery_test[test_name] = 'success'
        except Exception as e:
            summery_test[test_name] = 'failed'
            passed = False

        if i < len(test_name) - 1:
            print("sleeping for 30 seconds")
            time.sleep(30)

    print_summery(summery_test=summery_test, environment=environment)

    return passed, summery_test


def main():
    err, kubescape_exec, environments = get_args()
    if err is not None:
        return
    passed = True
    summery_tests = {}
    for environment in environments:
        p, summery_test = run_all_tests(kubescape_exec=kubescape_exec, environment=environment)
        passed = passed and p
        summery_tests[environment] = [summery_test, p]

    if len(summery_tests) > 1:
        print("\n\n\n======================SUMMERY TESTS=============\n")
        for k, v in summery_tests.items():
            en = k + ' success' if k[1] else k + ' failed'
            print_summery(summery_test=v[0], environment=en)
    if not passed:
        exit(1)


if __name__ == "__main__":
    main()
