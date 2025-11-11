# System Tests Infrastructure Guide

This guide explains the moving parts of the system-tests repository so that an AI agent (or any new contributor) can design, implement, and register a new end-to-end test without guesswork.

## Runtime Flow Overview

1. **CLI entrypoint** – `systest-cli.py` collects command-line arguments (test name, backend, customer, kwargs) and hydrates a `TestDriver`.
2. **Driver orchestration** – `TestDriver.main()` resolves credentials/backends, prepares temp directories, invokes `_run_test`, and persists a junit XML result. Cleanup and final reporting are handled even on failure.
3. **Configuration lookup** – `configurations/system/tests.py` maps the incoming test name to a configuration factory that returns a `TestConfiguration` (or domain-specific variant) containing metadata, fixtures, and the Python class that implements the test.
4. **Test execution class** – Each scenario lives under `tests_scripts/<domain>/` and is usually derived from `BaseTest` or a domain base like `BaseK8S` / `BaseKubescape`. The `start()` method implements the scenario, and `cleanup()` must leave no residues.
5. **Infrastructure helpers** – Utilities under `infrastructure/` (backend API, Kubernetes, Helm, Docker) and `systest_utils/` (logging, temp handling, JSON/YAML helpers) abstract external systems.
6. **Resource artefacts** – YAML manifests, expected JSON, and auxiliary files are stored beneath `configurations/` and `resources/`, and accessed via helper methods in `BaseTest`/`TestUtil`.
7. **Registration & scheduling** – `system_test_mapping.json` exposes tests to CI jobs and other repos, tagging each with owners, targets, and repositories. Jenkins jobs consume this to decide what to run.

### Key references

```37:112:/Users/eranmadar/repos/system-tests/test_driver.py
// ... existing code ...
        try:
            status, summary = self.run_test(backend=backend)
        except Exception as e:
            status = statics.FAILURE
            test_class_obj.failed()
// ... existing code ...
            if not cleanup_called and hasattr(test_class_obj, 'cleanup'):
                Logger.logger.info(f"Final safety cleanup attempt for test '{self.test_name}'")
                try:
                    test_class_obj.cleanup()
```

```33:214:/Users/eranmadar/repos/system-tests/tests_scripts/base_test.py
class BaseTest(object):
    def __init__(self, test_driver: driver.TestDriver, test_obj, backend: backend_api.ControlPanelAPI = None,
                 **kwargs):
        self.test_driver = test_driver
        self.test_obj = test_obj
        self.backend: backend_api.ControlPanelAPI = backend
        self.kwargs = kwargs
// ... existing code ...
    def cleanup(self, wlid: str = None, display_wt: bool = False):
        """Enhanced cleanup with tracking to prevent duplicates"""
        if self._cleanup_called:
            Logger.logger.info("Cleanup already called, skipping")
            return statics.SUCCESS, ""
```

```19:118:/Users/eranmadar/repos/system-tests/configurations/system/tests.py
def all_tests_names():
    tests = list()
    tests.extend(TestUtil.get_class_methods(KubescapeTests))
// ... existing code ...
def get_test(test_name):
    if test_name in TestUtil.get_class_methods(KubescapeTests):
        return KubescapeTests().__getattribute__(test_name)()
```

## Component Breakdown

### CLI and Driver

- **`systest-cli.py`** – Validates CLI options, resolves kwargs, initializes logging, and instantiates `TestDriver`.
- **`TestDriver`** – Loads backend/customer configurations, applies kwargs, maintains a per-run temp directory, and ensures cleanup happens even if exceptions bubble up.
- **Error handling** – On any failure, the driver marks the test as failed, attempts cleanup (`BaseTest.cleanup()`), and writes junit XML to `results_xml_format/`.

### Configuration Layer

- **`configurations/system/tests_cases/*`** – Each file groups related scenarios (kubescape, runtime, workflow). Every public `@staticmethod` constructs and returns a configuration object with:
  - `name`: canonical test name (function name).
  - `test_obj`: target class in `tests_scripts/...`.
  - Domain-specific kwargs: YAML names, namespaces, tenants, framework files, expected outputs, etc.
- **`configurations/system/tests.py`** – Provides `get_test(test_name)` and enumerates all registered names, acting as the single source of truth for discovery.
- **`system_test_mapping.json`** – Augments tests with metadata consumed by Jenkins and other repositories (targets, repo affinity, environment skips, owners, descriptions). Every runnable scenario must be listed here.

### Test Classes

- **Base classes**:
  - `tests_scripts/base_test.py` – Generic tenant management, cleanup orchestration, and helper methods for expected results, workloads, and tenant lifecycle.
  - `tests_scripts/kubernetes/base_k8s.py` – Kubernetes fixture management (namespaces, workloads, services).
  - `tests_scripts/kubescape/base_kubescape.py` – Kubescape CLI setup, scan execution, result parsing, and backend cleanup.
- **Domain scripts** – Reside under `tests_scripts/<domain>/`, each implementing a `start()` method that returns `(status, summary)` by calling `cleanup()`. Scripts should call `self.failed()` before raising or returning failure to let the framework handle cleanup policies correctly.

### Utilities and Wrappers

- **`infrastructure/`** – Wrappers for external services:
  - `backend_api.py` exposes REST helpers to the dashboard (`ControlPanelAPI`).
  - `helm_wrapper.py`, `kubectl_wrapper.py`, `docker_wrapper.py` encapsulate command-line interactions.
  - Specialized helpers (e.g., `aws.py`, `cacli_wrapper.py`, `scapy_wrapper.py`) support domain-specific flows.
- **`systest_utils/`** – Shared utility set:
  - `systests_utilities.py` provides filesystem helpers, subprocess execution, JSON/YAML loaders, HTTP polling, random IDs, and logging plumbing.
  - `statics.py` centralizes file path constants and well-known resource names for locating manifests and expected results.
  - `tests_logger.py` manages log formatting and stream capture.

### Artefact Layout

- **Kubernetes manifests** – Under `configurations/k8s_workloads/` grouped by resource type (deployments, services, secrets, etc.).
- **Expected results** – JSON snapshots live in `configurations/expected-result/` (and domain-specific subfolders). XML outputs for Jenkins reside in `results_xml_format/`.
- **Kubescape data** – Custom frameworks, exceptions, and expected results under `configurations/ks-*`.
- **Misc assets** – Additional scenarios and mocks stored in `configurations/scenarios-*` and `resources/`.

### Environment & Dependencies

- Virtual environment is bootstrapped via `create_env.sh` and lives in `systests_python_env/`.
- `requirements.txt` lists Python dependencies. Reinstall after updates to ensure reproducible environments.
- Runtime credentials (customer, username/password, tokens) are expected via environment variables as documented in `readme.md`.
- External tooling: Docker, kubectl, Helm, minikube/cluster access, and optionally AWS CLI depending on the test scenario.

### Lifecycle Expectations

1. **Init** – Base classes capture metadata, configure backend access, and parse kwargs.
2. **Start** – Implement test logic: deploy fixtures, run scans, trigger APIs, and assert outcomes.
3. **Cleanup** – Must tear down tenants, namespaces, workloads, and backend state. `BaseTest.cleanup()` removes created tenants; `BaseKubescape.cleanup()` handles cluster removal and config deletion.
4. **Failure paths** – Call `self.failed()` before raising to let the framework skip destructive cleanup if the `delete_test_tenant` policy dictates.

## Building a Test from Scratch

1. **Analyse the scenario**
   - Identify the domain (kubescape, runtime, payments, etc.).
   - Determine the required backend APIs, Kubernetes resources, or external systems.

2. **Locate or create fixtures**
   - Store YAMLs, JSON expected results, and auxiliary data in the appropriate `configurations/` or `resources/` subfolder.
   - Reference files via helper methods (e.g., `BaseTest.get_workload_templates_paths`, `TestUtil.get_abs_path`).

3. **Implement the test class**
   - Add a new Python file or class under `tests_scripts/<domain>/`.
   - Inherit from the nearest base class (`BaseTest`, `BaseK8S`, `BaseKubescape`, etc.).
   - Implement `start()` to orchestrate the scenario and return `self.cleanup()` at the end.
   - Use utilities from `infrastructure/` instead of shelling out directly.
   - Ensure every resource you create is tracked for cleanup (tenants via `track_tenant_creation`, workloads via `BaseK8S` helpers).

4. **Expose configuration**
   - Add a static method in the relevant `configurations/system/tests_cases/<domain>_tests.py` returning the proper configuration object.
   - Pass arguments (e.g., `yaml`, `namespace`, `framework_file`, `create_test_tenant`) that your test class consumes.

5. **Register metadata**
   - Append an entry for the new test in `system_test_mapping.json` with targets, repositories, environments to skip, description, and owner.

6. **Run locally**
   - Activate the virtual environment and execute `python systest-cli.py -t <test-name> -b <backend> -c <customer> [--kwargs ...]`.
   - Inspect logs and junit output under `results_xml_format/`.

7. **Validate in CI**
   - Duplicate `CAA_Single_System_Tests` and point it to your branch.
   - Confirm the test passes before merging and, if needed, add it to the shared Jenkinsfiles.

## AI Agent Checklist

- [ ] Gather requirements (domain, API calls, Kubernetes assets).
- [ ] Check existing folders under `tests_scripts/` and `configurations/` for reusable components.
- [ ] Scaffold/extend a test class with `start()` and `cleanup()` that relies only on repository utilities.
- [ ] Wire configuration and register in `system_test_mapping.json`.
- [ ] Execute locally, collect logs, ensure cleanup works on success and failure.
- [ ] Document nuances (new fixtures, environment variables) in `DEVELOPMENT.md` if needed.

## Common Tasks & Pointers

- **Create tenant** – Use `BaseTest.create_new_tenant()`; track IDs for deletion.
- **Apply Kubernetes YAML** – Inherit from `BaseK8S` or `BaseKubescape` and call `apply_yaml_file`.
- **Trigger backend checks** – Access REST endpoints through `infrastructure/backend_api.py` rather than raw `requests`.
- **Wait for reporting data** – Reuse polling helpers like `BaseTest.wait_for_report` or `TestUtil.constant_get_request`.
- **Compare JSON outputs** – `TestUtil.compare_with_expected_file` performs tolerant comparisons with optional exclude paths.

By following this guide, an AI agent can confidently navigate the repository, pick the right abstractions, and deliver a complete, production-ready system test. The README and `DEVELOPMENT.md` complement this document for environment setup and workflow policies.

