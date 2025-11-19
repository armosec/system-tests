"""
Runtime Stress Test
This test generates configurable load on the runtime detection system to test performance,
scalability, and resilience under stress conditions.
"""

import json
import time
import threading
import random
from datetime import datetime, timezone
from typing import List, Optional
from dataclasses import dataclass, field

from configurations.system.tests_cases.structures import TestConfiguration
from systest_utils import statics, Logger
from tests_scripts.helm.base_helm import BaseHelm


@dataclass
class AlertProfile:
    """Configuration for a specific type of alert generation"""
    name: str
    rate_per_minute: int
    is_trigger: bool  # True = should generate incident, False = benign activity
    command: str
    description: str = ""
    use_shell: bool = False
    worker_count: int = 1  # Number of parallel workers generating this alert


@dataclass
class NamespaceContext:
    """Represents a namespace under stress (within the same tenant/cluster)"""
    index: int
    namespace: str
    wlids: List[str] = field(default_factory=list)


@dataclass
class StressTestConfig:
    """Configuration for the stress test - creates multiple namespaces in the same tenant/cluster"""
    namespace_count: int  # Number of namespaces to create (all in same tenant) - REQUIRED
    duration_minutes: int  # Test duration in minutes - REQUIRED
    ramp_up_seconds: int = 60  # Optional: gradual load increase time
    alert_profiles: List[AlertProfile] = field(default_factory=list)  # REQUIRED (validated separately)
    pods_per_namespace: int = 1  # Optional: number of pods per namespace
    
    
    def total_alerts_per_minute(self) -> int:
        """Calculate total expected alerts per minute"""
        return sum(profile.rate_per_minute for profile in self.alert_profiles)
    
    def total_expected_alerts(self) -> int:
        """Calculate total expected alerts for entire test duration"""
        return self.total_alerts_per_minute() * self.duration_minutes
    
    def to_dict(self) -> dict:
        """Convert to dictionary for logging/reporting"""
        return {
            "namespace_count": self.namespace_count,
            "duration_minutes": self.duration_minutes,
            "ramp_up_seconds": self.ramp_up_seconds,
            "pods_per_namespace": self.pods_per_namespace,
            "alert_profiles": [
                {
                    "name": p.name,
                    "rate_per_minute": p.rate_per_minute,
                    "is_trigger": p.is_trigger,
                    "description": p.description
                }
                for p in self.alert_profiles
            ],
            "total_alerts_per_minute": self.total_alerts_per_minute(),
            "total_expected_alerts": self.total_expected_alerts()
        }


@dataclass
class StressTestStats:
    """Basic execution stats for monitoring"""
    start_time: datetime
    end_time: Optional[datetime] = None
    commands_executed: int = 0
    commands_failed: int = 0
    errors: List[str] = field(default_factory=list)
    
    def duration_seconds(self) -> float:
        """Calculate test duration in seconds"""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return (datetime.now(timezone.utc) - self.start_time).total_seconds()
    
    def success_rate(self) -> float:
        """Calculate command success rate as percentage"""
        total = self.commands_executed + self.commands_failed
        if total == 0:
            return 0.0
        return (self.commands_executed / total) * 100


class RuntimeStressTest(BaseHelm):
    """
    Runtime Stress Test - Validates runtime detection system under load
    
    This test:
    1. Deploys multiple workloads (simulating multiple tenants)
    2. Generates configurable alert load (both trigger and non-trigger)
    3. Monitors system behavior and metrics
    4. Validates system stability and performance under stress
    """

    def __init__(self, test_obj: TestConfiguration = None, backend=None, 
                 test_driver=None, kubernetes_obj=None):
        super(RuntimeStressTest, self).__init__(
            test_obj=test_obj, 
            backend=backend, 
            test_driver=test_driver, 
            kubernetes_obj=kubernetes_obj
        )
        
        # Helm configuration for runtime detection
        self.helm_kwargs = {
            "capabilities.manageWorkloads": "enable",
            "capabilities.configurationScan": "disable",
            "capabilities.continuousScan": "disable",
            "capabilities.nodeScan": "disable",
            "capabilities.vulnerabilityScan": "disable",
            "grypeOfflineDB.enabled": "false",
            "capabilities.relevancy": "enable",
            "capabilities.runtimeObservability": "enable",
            "capabilities.malwareDetection": "enable",
            "capabilities.runtimeDetection": "enable",
            "capabilities.nodeProfileService": "enable",
            "alertCRD.installDefault": True,
            "alertCRD.scopeClustered": True,
            # Short learning period for faster testing
            "nodeAgent.config.maxLearningPeriod": "60s",
            "nodeAgent.config.learningPeriod": "50s",
            "nodeAgent.config.updatePeriod": "30s",
            "nodeAgent.config.nodeProfileInterval": "1m",
            "logger.level": "debug",
            "capabilities.httpDetection": "disable",
            "capabilities.admissionController": "disable",
            "capabilities.networkEventsStreaming": "enable",
            "capabilities.nodeSbomGeneration": "disable",
            "nodeAgent.config.networkStreamingInterval": "5s",
            "nodeAgent.config.profilesCacheRefreshRate": "5s",
        }
        
        # Override with test-specific helm kwargs if provided
        test_helm_kwargs = self.test_obj.get_arg("helm_kwargs")
        if test_helm_kwargs:
            self.helm_kwargs.update(test_helm_kwargs)
        
        # Load stress test configuration
        self.config = self._load_config()
        
        # Basic execution stats (metrics come from backend)
        self.stats = StressTestStats(start_time=datetime.now(timezone.utc))
        
        # State management
        self.wlids: List[str] = []
        self.namespaces: List[str] = []
        self.is_running: bool = False
        self.threads: List[threading.Thread] = []
        self.namespace_contexts: List[NamespaceContext] = []
        self.all_wlids: List[str] = []

    def _load_config(self) -> StressTestConfig:
        """Load and validate stress test configuration - MUST be provided by user"""
        config_dict = self.test_obj.get_arg("stress_config", None)
        
        # Configuration is REQUIRED
        if config_dict is None:
            raise ValueError(
                "stress_config is required! Please provide configuration in your test definition.\n"
                "Example:\n"
                "stress_config={\n"
                "    'namespace_count': 1,\n"
                "    'duration_minutes': 10,\n"
                "    'ramp_up_seconds': 60,\n"
                "    'pods_per_namespace': 1,\n"
                "    'alert_profiles': [...]\n"
                "}"
            )
        
        # Validate required fields
        required_fields = ["namespace_count", "duration_minutes", "alert_profiles"]
        missing_fields = [field for field in required_fields if field not in config_dict]
        if missing_fields:
            raise ValueError(
                f"Missing required fields in stress_config: {missing_fields}\n"
                f"Required: namespace_count, duration_minutes, alert_profiles"
            )
        
        # Create config from provided parameters (NO DEFAULTS for required fields)
        config = StressTestConfig(
            namespace_count=config_dict["namespace_count"],
            duration_minutes=config_dict["duration_minutes"],
            ramp_up_seconds=config_dict.get("ramp_up_seconds", 60),  # Optional with default
            pods_per_namespace=config_dict.get("pods_per_namespace", 1)  # Optional with default
        )
        
        # Load alert profiles (REQUIRED)
        config.alert_profiles = [
            AlertProfile(**profile) for profile in config_dict["alert_profiles"]
        ]
        
        # Validate at least one alert profile
        if not config.alert_profiles:
            raise ValueError("At least one alert profile must be defined in stress_config")
        
        Logger.logger.info(f"Loaded stress test configuration: {json.dumps(config.to_dict(), indent=2)}")
        return config

    def start(self):
        """Main test execution flow"""
        assert self.backend is not None, f"The test {self.test_driver.test_name} must run with backend"
        
        Logger.logger.info("=" * 80)
        Logger.logger.info("RUNTIME STRESS TEST - Starting")
        Logger.logger.info("=" * 80)
        Logger.logger.info(f"Configuration: {json.dumps(self.config.to_dict(), indent=2)}")
        
        try:
            # Phase 1: Setup
            cluster, base_namespace = self.setup()
            namespace_count = max(1, self.config.namespace_count)
            
            # Phase 2: Install Kubescape with runtime detection (single installation for all namespaces)
            Logger.logger.info("Installing Kubescape with runtime detection capabilities")
            self.add_and_upgrade_armo_to_repo()
            self.install_armo_helm_chart(helm_kwargs=self.helm_kwargs)
            self.wait_for_report(
                self.verify_running_pods, 
                sleep_interval=5, 
                timeout=360,
                namespace=statics.CA_NAMESPACE_FROM_HELM_NAME
            )
            # Phase 3: Initialize namespaces and deploy workloads
            Logger.logger.info(f"Preparing {namespace_count} namespace(s) with {self.config.pods_per_namespace} pod(s) each")
            self._initialize_namespaces(cluster=cluster, base_namespace=base_namespace, namespace_count=namespace_count)
            
            # Phase 5: Execute stress test
            Logger.logger.info("Starting stress test execution")
            self._execute_stress_test()
            
            # Phase 6: Verify system is working
            Logger.logger.info("Verifying runtime detection system")
            self.wait_for_report(
                self.verify_kdr_monitored_counters, 
                sleep_interval=25, 
                timeout=600, 
                cluster=cluster
            )
            
            Logger.logger.info("=" * 80)
            Logger.logger.info("RUNTIME STRESS TEST - Completed Successfully")
            Logger.logger.info(f"Duration: {self.stats.duration_seconds():.0f}s")
            Logger.logger.info(f"Commands executed: {self.stats.commands_executed}")
            Logger.logger.info(f"Success rate: {self.stats.success_rate():.2f}%")
            Logger.logger.info("Check backend dashboards for detailed metrics:")
            Logger.logger.info("  - Telematics: Alert ingestion and processing")
            Logger.logger.info("  - Backlog: Incident creation and handling")
            Logger.logger.info("=" * 80)
            
        except Exception as e:
            Logger.logger.error(f"Stress test failed: {e}")
            self.stats.errors.append(str(e))
            raise
        finally:
            self.stats.end_time = datetime.now(timezone.utc)
            self.is_running = False
            
        return self.cleanup()

    def _deploy_workloads(self, cluster: str, namespace: str):
        """Deploy workloads for stress testing"""
        Logger.logger.info(f"Deploying workloads to namespace: {namespace}")
        
        deployments_path = self.test_obj["deployments"]
        workload_objs = self.apply_directory(path=deployments_path, namespace=namespace)
        
        # Get WLIDs for all deployed workloads
        wlids = self.get_wlid(workload=workload_objs, namespace=namespace, cluster=cluster)
        if isinstance(wlids, str):
            wlids = [wlids]
        
        # Deduplicate while preserving order
        unique_wlids = list(dict.fromkeys(wlids))
        for wlid in unique_wlids:
            if wlid not in self.wlids:
                self.wlids.append(wlid)
        
        Logger.logger.info(f"Deployed {len(unique_wlids)} workload(s): {unique_wlids}")
        
        # Wait for pods to be running
        self.wait_for_report(
            self.verify_running_pods, 
            sleep_interval=5, 
            timeout=180, 
            namespace=namespace
        )
        
        return unique_wlids

    def _wait_for_application_profiles(self, wlids: List[str], namespace: str):
        """Wait until application profiles exist and are complete"""
        if not wlids:
            raise Exception("No workloads deployed")
        
        Logger.logger.info(f"Waiting for application profiles for namespace '{namespace}' ({len(wlids)} workload(s))")
        self.wait_for_report(
            self.verify_application_profiles, 
            wlids=wlids, 
            namespace=namespace
        )
        Logger.logger.info("Application profiles are ready")

    def _initialize_namespaces(self, cluster: str, base_namespace: str, namespace_count: int):
        """Create multiple namespaces (within same tenant/cluster) and deploy workloads in parallel"""
        self.namespace_contexts.clear()
        self.all_wlids.clear()

        # Phase 1: Deploy all workloads in parallel
        Logger.logger.info(f"Deploying workloads to {namespace_count} namespace(s) in parallel...")
        
        # Prepare list of namespaces
        namespaces_to_deploy = [base_namespace]
        for ns_index in range(1, namespace_count):
            namespace = self.create_namespace()
            namespaces_to_deploy.append(namespace)
        
        # Deploy workloads in parallel using threads
        deployment_results = []
        deployment_threads = []
        
        def deploy_to_namespace(ns, ns_idx):
            Logger.logger.info(f"[Thread-{ns_idx}] Deploying to namespace: {ns}")
            wlids = self._deploy_workloads(cluster=cluster, namespace=ns)
            Logger.logger.info(f"[Thread-{ns_idx}] Deployed {len(wlids)} workload(s) to {ns}")
            return (ns_idx, ns, wlids)
        
        # Start deployment threads
        for idx, ns in enumerate(namespaces_to_deploy):
            thread = threading.Thread(
                target=lambda i=idx, n=ns: deployment_results.append(deploy_to_namespace(n, i)),
                name=f"Deploy-{idx}"
            )
            thread.start()
            deployment_threads.append(thread)
        
        # Wait for all deployments to complete
        for thread in deployment_threads:
            thread.join()
        
        Logger.logger.info(f"All workloads deployed. Waiting for pods to be running...")
        
        # Wait for all pods to be running (done per namespace, but could be optimized)
        for idx, ns in enumerate(namespaces_to_deploy):
            self.wait_for_report(
                self.verify_running_pods,
                sleep_interval=5,
                timeout=180,
                namespace=ns
            )
        
        # Phase 2: Wait for application profiles in parallel
        Logger.logger.info(f"Waiting for application profiles to complete in parallel...")
        
        profile_threads = []
        
        def wait_for_profiles(ns, wlids_list):
            Logger.logger.info(f"[Profiles] Waiting for {ns}...")
            self._wait_for_application_profiles(wlids=wlids_list, namespace=ns)
            Logger.logger.info(f"[Profiles] {ns} profiles ready")
        
        # Build namespace contexts and start profile waiting threads
        for idx, ns, wlids in sorted(deployment_results):
            self.namespace_contexts.append(NamespaceContext(index=idx, namespace=ns, wlids=wlids))
            
            thread = threading.Thread(
                target=wait_for_profiles,
                args=(ns, wlids),
                name=f"Profiles-{idx}"
            )
            thread.start()
            profile_threads.append(thread)
        
        # Wait for all profile checks to complete
        for thread in profile_threads:
            thread.join()
        
        self.all_wlids = [wlid for ns_ctx in self.namespace_contexts for wlid in ns_ctx.wlids]
        Logger.logger.info(f"✓ Prepared {len(self.namespace_contexts)} namespace(s) with {len(self.all_wlids)} workload(s) total")

    def _execute_stress_test(self):
        """Execute the stress test with configured load"""
        Logger.logger.info("=" * 80)
        Logger.logger.info("STRESS TEST EXECUTION - Starting load generation")
        Logger.logger.info("=" * 80)
        
        self.is_running = True
        self.stats.start_time = datetime.now(timezone.utc)
        
        # Start alert generation threads for each profile
        for profile in self.config.alert_profiles:
            workers = max(1, profile.worker_count)
            for worker_idx in range(workers):
                thread = threading.Thread(
                    target=self._generate_alerts_for_profile,
                    args=(profile, worker_idx),
                    name=f"AlertGen-{profile.name}-w{worker_idx}"
                )
                thread.daemon = True
                thread.start()
                self.threads.append(thread)
            Logger.logger.info(
                f"Started {workers} alert generation worker(s) for profile: {profile.name}"
            )
        
        # Monitor test execution
        start_time = time.time()
        test_duration = self.config.duration_minutes * 60
        
        while self.is_running and (time.time() - start_time) < test_duration:
            elapsed = time.time() - start_time
            remaining = test_duration - elapsed
            
            Logger.logger.info(
                f"Stress test progress: {elapsed:.0f}s elapsed, {remaining:.0f}s remaining "
                f"| Commands: {self.stats.commands_executed} success, {self.stats.commands_failed} failed"
            )
            time.sleep(30)  # Status update every 30 seconds
        
        # Stop test
        self.is_running = False
        Logger.logger.info("Stopping stress test - waiting for threads to complete")
        
        # Wait for all threads to complete
        for thread in self.threads:
            thread.join(timeout=10)
        
        self.stats.end_time = datetime.now(timezone.utc)
        
        Logger.logger.info("=" * 80)
        Logger.logger.info("STRESS TEST EXECUTION - Completed")
        Logger.logger.info("=" * 80)

    def _generate_alerts_for_profile(self, profile: AlertProfile, worker_idx: int = 0):
        """Generate alerts according to the profile configuration"""
        interval = 60.0 / profile.rate_per_minute if profile.rate_per_minute > 0 else 60
        
        Logger.logger.info(
            f"Alert generator [{profile.name}][worker={worker_idx}] started: "
            f"{profile.rate_per_minute}/min (every {interval:.2f}s)"
        )
        
        while self.is_running:
            try:
                # Execute command on first workload
                target_wlid = random.choice(self.all_wlids) if self.all_wlids else None
                if target_wlid:
                    exec_command = ["/bin/sh", "-c", profile.command] if profile.use_shell else profile.command
                    self.exec_pod(
                        wlid=target_wlid,
                        command=exec_command,
                        splitCmd=not isinstance(exec_command, list)
                    )
                    self.stats.commands_executed += 1
                    
                    if profile.is_trigger:
                        Logger.logger.debug(
                            f"Triggered alert: {profile.name} | worker={worker_idx} | wlid={target_wlid}"
                        )
                    
            except Exception as e:
                self.stats.commands_failed += 1
                Logger.logger.warning(
                    f"Alert generation failed [{profile.name}][worker={worker_idx}]: {e}"
                )
            
            # Wait for next execution
            time.sleep(interval)
        
        Logger.logger.info(f"Alert generator [{profile.name}][worker={worker_idx}] stopped")


    def verify_kdr_monitored_counters(self, cluster: str):
        """Verify KDR monitored asset counters"""
        Logger.logger.info("Verifying KDR monitored counters")
        resp = self.backend.get_kdr_monitored_counters(cluster=cluster)
        assert resp is not None, f"Failed to get monitored assets {json.dumps(resp)}"
        assert resp.get("clustersCount", 0) > 0, f"No clusters monitored {json.dumps(resp)}"
        assert resp.get("podsCount", 0) > 0, f"No pods monitored {json.dumps(resp)}"
        Logger.logger.info(f"Monitored assets: {json.dumps(resp)}")

    def cleanup(self, **kwargs):
        """Cleanup resources after test"""
        Logger.logger.info("Cleaning up stress test resources")
        self.is_running = False
        
        # Wait for all threads to finish
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        return super().cleanup(**kwargs)

