"""
Backend Stress Test - Direct HTTP Alert Simulation

This test sends runtime alerts directly to the in-cluster synchronizer via HTTP,
bypassing the node-agent. This tests the backend's alert processing capacity.

The test workflow:
1. Install Helm chart (Kubescape with synchronizer) - same as RuntimeStressTest
2. Deploy workloads to the cluster - same as RuntimeStressTest  
3. Wait for application profiles - same as RuntimeStressTest
4. Send HTTP POST requests directly to the synchronizer (bypassing node-agent)
"""

import json
import time
import threading
import random
import uuid
import requests
import subprocess
from datetime import datetime, timezone
from typing import List, Optional
from dataclasses import dataclass, field

from configurations.system.tests_cases.structures import TestConfiguration
from systest_utils import Logger, statics
from tests_scripts.helm.base_helm import BaseHelm


@dataclass
class BackendAlertProfile:
    """Configuration for a specific type of alert to send to backend"""
    name: str
    rate_per_minute: int
    worker_count: int = 1
    alert_name: str = "Unexpected system call"
    rule_id: str = "R0003"
    severity: int = 1
    description: str = ""
    syscall: str = "sched_yield"  # Default syscall for variation


@dataclass
class BackendStressConfig:
    """Configuration for backend-only stress test"""
    duration_minutes: int  # Test duration in minutes - REQUIRED
    alert_profiles: List[BackendAlertProfile] = field(default_factory=list)  # REQUIRED
    synchronizer_url: str = "http://synchronizer.kubescape.svc.cluster.local:8089/apis/v1/kubescape.io"  # In-cluster
    cluster_name: str = "stress-test-cluster"
    namespace: str = "stress-test-namespace"
    
    def total_alerts_per_minute(self) -> int:
        """Calculate total expected alerts per minute across all workers"""
        return sum(profile.rate_per_minute * profile.worker_count for profile in self.alert_profiles)
    
    def total_expected_alerts(self) -> int:
        """Calculate total expected alerts for entire test duration"""
        return self.total_alerts_per_minute() * self.duration_minutes


@dataclass
class BackendStressStats:
    """Execution stats for monitoring"""
    start_time: datetime
    end_time: Optional[datetime] = None
    alerts_sent: int = 0
    alerts_failed: int = 0
    errors: List[str] = field(default_factory=list)
    
    def duration_seconds(self) -> float:
        """Calculate test duration in seconds"""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return (datetime.now(timezone.utc) - self.start_time).total_seconds()
    
    def success_rate(self) -> float:
        """Calculate success rate as percentage"""
        total = self.alerts_sent + self.alerts_failed
        if total == 0:
            return 0.0
        return (self.alerts_sent / total) * 100
    
    def alerts_per_second(self) -> float:
        """Calculate average alerts per second"""
        duration = self.duration_seconds()
        if duration == 0:
            return 0.0
        return self.alerts_sent / duration


class BackendStressTest(BaseHelm):
    """
    Backend Stress Test - Sends alerts directly to synchronizer via HTTP
    
    This test installs Kubescape/synchronizer in your cluster (like RuntimeStressTest),
    but instead of using kubectl exec to trigger alerts via node-agent, it sends
    HTTP POST requests directly to the in-cluster synchronizer.
    
    Workflow:
    1. Install Helm chart (Kubescape/synchronizer)
    2. Deploy workloads
    3. Wait for application profiles
    4. Send HTTP alerts directly to synchronizer
    """
    
    def __init__(self, test_obj: TestConfiguration = None, backend=None,
                 test_driver=None, kubernetes_obj=None):
        super(BackendStressTest, self).__init__(
            test_obj=test_obj,
            backend=backend,
            test_driver=test_driver,
            kubernetes_obj=kubernetes_obj
        )
        
        # Helm configuration - SAME as RuntimeStressTest
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
        
        # Load backend stress test configuration
        self.config = self._parse_config()
        self.stats = BackendStressStats(start_time=datetime.now(timezone.utc))
        
        # State management
        self.wlids: List[str] = []
        self.is_running: bool = False
        self.threads: List[threading.Thread] = []
        self.customer_guid: Optional[str] = None
        self.port_forward_process: Optional[subprocess.Popen] = None  # Port-forward process
        
        Logger.logger.info("Backend Stress Test initialized")
        Logger.logger.info(f"Configuration: {json.dumps(self._config_summary(), indent=2)}")
    
    def _parse_config(self) -> BackendStressConfig:
        """Parse and validate the configuration dictionary"""
        config_dict = self.test_obj.get_arg("backend_stress_config")
        if not config_dict:
            raise ValueError("backend_stress_config is required")
        
        try:
            alert_profiles = [BackendAlertProfile(**p) for p in config_dict.get("alert_profiles", [])]
            config = BackendStressConfig(
                duration_minutes=config_dict["duration_minutes"],
                alert_profiles=alert_profiles,
                synchronizer_url=config_dict.get("synchronizer_url", "http://synchronizer.kubescape.svc.cluster.local:8089/apis/v1/kubescape.io"),
                cluster_name=config_dict.get("cluster_name", "stress-test-cluster"),
                namespace=config_dict.get("namespace", "stress-test-namespace")
            )
            if not config.alert_profiles:
                raise ValueError("At least one alert_profile must be provided")
            return config
        except KeyError as e:
            raise ValueError(f"Missing required configuration key: {e}")
        except Exception as e:
            raise ValueError(f"Invalid backend stress test configuration: {e}")

    def _config_summary(self) -> dict:
        """Return a summary of the configuration for logging"""
        return {
            "duration_minutes": self.config.duration_minutes,
            "synchronizer_url": self.config.synchronizer_url,
            "cluster_name": self.config.cluster_name,
            "namespace": self.config.namespace,
            "alert_profiles": [
                {
                    "name": p.name,
                    "rate_per_minute": p.rate_per_minute,
                    "worker_count": p.worker_count,
                    "total_rate": p.rate_per_minute * p.worker_count
                }
                for p in self.config.alert_profiles
            ],
            "total_alerts_per_minute": self.config.total_alerts_per_minute(),
            "total_expected_alerts": self.config.total_expected_alerts()
        }
    
    def start(self):
        """Main test execution flow - SAME pattern as RuntimeStressTest"""
        assert self.backend is not None, f"The test {self.test_driver.test_name} must run with backend"
        
        Logger.logger.info("=" * 80)
        Logger.logger.info("BACKEND STRESS TEST - Starting")
        Logger.logger.info("=" * 80)
        
        try:
            # Get customer GUID from backend
            self.customer_guid = self.backend.get_customer_guid()
            Logger.logger.info(f"Customer GUID: {self.customer_guid}")
            
            # Phase 1: Setup cluster
            cluster, namespace = self.setup()
            
            # Phase 2: Install Kubescape with runtime detection (SAME as RuntimeStressTest)
            Logger.logger.info("Installing Kubescape with runtime detection capabilities")
            self.add_and_upgrade_armo_to_repo()
            self.install_armo_helm_chart(helm_kwargs=self.helm_kwargs)
            self.wait_for_report(
                self.verify_running_pods,
                sleep_interval=5,
                timeout=360,
                namespace=statics.CA_NAMESPACE_FROM_HELM_NAME
            )
            
            # Phase 2.5: Setup port-forward to synchronizer (if using localhost)
            if "localhost" in self.config.synchronizer_url:
                self._setup_port_forward()
            
            # Phase 3: Deploy workloads (SAME as RuntimeStressTest)
            Logger.logger.info(f"Deploying workloads to namespace: {namespace}")
            self._deploy_workloads(cluster=cluster, namespace=namespace)
            
            # Phase 4: Wait for application profiles (SAME as RuntimeStressTest)
            Logger.logger.info("Waiting for application profiles")
            self._wait_for_application_profiles(wlids=self.wlids, namespace=namespace)
            
            # Phase 5: Execute stress test (DIFFERENT - HTTP instead of kubectl exec)
            Logger.logger.info("Starting backend stress test execution")
            self._execute_stress_test(cluster=cluster)
            
            # Phase 6: Print results
            self._print_results()
            
            Logger.logger.info("=" * 80)
            Logger.logger.info("BACKEND STRESS TEST - Completed Successfully")
            Logger.logger.info("=" * 80)
            
        except Exception as e:
            Logger.logger.error(f"Backend stress test failed: {e}", exc_info=True)
            raise
        finally:
            self.stats.end_time = datetime.now(timezone.utc)
            self.is_running = False
        
        return self.cleanup()
    
    def _setup_port_forward(self):
        """Setup port-forward to synchronizer service"""
        Logger.logger.info("Setting up port-forward to synchronizer service")
        Logger.logger.info("Running: kubectl port-forward -n kubescape svc/synchronizer 8089:8089")
        
        try:
            # Start port-forward in background
            self.port_forward_process = subprocess.Popen(
                ["kubectl", "port-forward", "-n", "kubescape", "svc/synchronizer", "8089:8089"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Give it a moment to start
            time.sleep(3)
            
            # Check if process is still running
            if self.port_forward_process.poll() is not None:
                stdout, stderr = self.port_forward_process.communicate()
                raise RuntimeError(f"Port-forward failed to start: {stderr.decode()}")
            
            Logger.logger.info("✓ Port-forward to synchronizer established (localhost:8089 -> synchronizer:8089)")
            
        except Exception as e:
            Logger.logger.error(f"Failed to setup port-forward: {e}")
            raise
    
    def _teardown_port_forward(self):
        """Teardown port-forward to synchronizer service"""
        if self.port_forward_process:
            Logger.logger.info("Tearing down port-forward to synchronizer")
            try:
                self.port_forward_process.terminate()
                self.port_forward_process.wait(timeout=5)
                Logger.logger.info("✓ Port-forward terminated")
            except Exception as e:
                Logger.logger.warning(f"Error terminating port-forward: {e}")
                try:
                    self.port_forward_process.kill()
                except:
                    pass
            finally:
                self.port_forward_process = None
    
    def _deploy_workloads(self, cluster: str, namespace: str):
        """Deploy workloads for stress testing - SAME as RuntimeStressTest"""
        Logger.logger.info(f"Deploying workloads to namespace: {namespace}")
        
        deployments_path = self.test_obj.get_arg("deployments")
        if not deployments_path:
            # Use default path if not provided
            from os.path import join
            from systest_utils.statics import DEFAULT_DEPLOYMENT_PATH
            deployments_path = join(DEFAULT_DEPLOYMENT_PATH, "redis_sleep_long")
        
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
        """Wait until application profiles exist and are complete - SAME as RuntimeStressTest"""
        if not wlids:
            raise Exception("No workloads deployed")
        
        Logger.logger.info(f"Waiting for application profiles ({len(wlids)} workload(s))")
        self.wait_for_report(
            self.verify_application_profiles,
            wlids=wlids,
            namespace=namespace
        )
        Logger.logger.info("Application profiles are ready")
    
    def _execute_stress_test(self, cluster: str):
        """Execute the stress test - send HTTP alerts to synchronizer"""
        Logger.logger.info("=" * 80)
        Logger.logger.info("BACKEND STRESS TEST EXECUTION - Starting alert generation")
        Logger.logger.info("=" * 80)
        
        self.is_running = True
        self.stats.start_time = datetime.now(timezone.utc)
        
        # Start alert generation threads for each profile
        for profile in self.config.alert_profiles:
            for worker_idx in range(profile.worker_count):
                thread = threading.Thread(
                    target=self._send_alerts_for_profile,
                    args=(profile, worker_idx, cluster),
                    name=f"AlertSender-{profile.name}-Worker-{worker_idx}"
                )
                thread.daemon = True
                thread.start()
                self.threads.append(thread)
            
            total_rate = profile.rate_per_minute * profile.worker_count
            Logger.logger.info(
                f"Started alert sender: {profile.name} ({profile.worker_count} worker(s)) - {total_rate}/min total"
            )
        
        # Monitor test execution
        start_time = time.time()
        test_duration = self.config.duration_minutes * 60
        
        while self.is_running and (time.time() - start_time) < test_duration:
            elapsed = time.time() - start_time
            remaining = test_duration - elapsed
            
            Logger.logger.info(
                f"Progress: {elapsed:.0f}s elapsed, {remaining:.0f}s remaining "
                f"| Alerts: {self.stats.alerts_sent} sent, {self.stats.alerts_failed} failed "
                f"| Rate: {self.stats.alerts_per_second():.1f}/s"
            )
            time.sleep(30)  # Status update every 30 seconds
        
        # Stop test
        self.is_running = False
        Logger.logger.info("Stopping backend stress test - waiting for threads to complete")
        
        # Wait for all threads to complete
        for thread in self.threads:
            thread.join(timeout=10)
        
        self.stats.end_time = datetime.now(timezone.utc)
        
        Logger.logger.info("=" * 80)
        Logger.logger.info("BACKEND STRESS TEST EXECUTION - Completed")
        Logger.logger.info("=" * 80)

    def _send_alerts_for_profile(self, profile: BackendAlertProfile, worker_idx: int, cluster: str):
        """Generate and send alerts according to the profile configuration"""
        interval = 60.0 / profile.rate_per_minute if profile.rate_per_minute > 0 else 60
        
        Logger.logger.info(
            f"Alert sender [{profile.name}] worker {worker_idx} started: "
            f"{profile.rate_per_minute}/min (every {interval:.3f}s)"
        )
        
        # Append /v1/runtimealerts to the base URL (same as node-agent does)
        url = self.config.synchronizer_url
        if not url.endswith("/v1/runtimealerts"):
            url = url.rstrip("/") + "/v1/runtimealerts"
        
        error_count = 0
        last_error_log_time = 0
        error_log_interval = 10  # Log errors at most once every 10 seconds
        
        while self.is_running:
            try:
                payload = self._create_alert_payload(profile, cluster)
                
                # Retry logic with exponential backoff for transient errors
                max_retries = 3
                retry_delay = 0.1
                success = False
                
                for attempt in range(max_retries):
                    try:
                        response = requests.post(
                            url,
                            json=payload,
                            timeout=30,  # Increased timeout for slow processing
                            headers={"Content-Type": "application/json"}
                        )
                        response.raise_for_status()
                        self.stats.alerts_sent += 1
                        success = True
                        error_count = 0  # Reset error count on success
                        break
                    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                        # Retry on timeout/connection errors
                        if attempt < max_retries - 1:
                            time.sleep(retry_delay * (2 ** attempt))  # Exponential backoff
                            continue
                        else:
                            raise  # Re-raise on final attempt
                
                if not success:
                    raise requests.exceptions.RequestException("Failed after retries")
                    
            except requests.exceptions.RequestException as e:
                self.stats.alerts_failed += 1
                error_count += 1
                
                # Only log errors periodically to reduce noise
                current_time = time.time()
                if current_time - last_error_log_time >= error_log_interval:
                    error_details = str(e)
                    if hasattr(e, 'response') and e.response is not None:
                        try:
                            error_details = f"{e} - Response: {e.response.text[:200]}"
                        except:
                            pass
                    Logger.logger.warning(
                        f"Alert send failures [{profile.name}] worker {worker_idx}: "
                        f"{error_count} recent errors (last: {error_details[:100]})"
                    )
                    last_error_log_time = current_time
                    error_count = 0
                
                if len(self.stats.errors) < 100:
                    self.stats.errors.append(f"[{profile.name}] worker {worker_idx}: {str(e)[:200]}")
                
                # Add small delay after errors to avoid overwhelming the synchronizer
                time.sleep(0.1)
                
            except Exception as e:
                self.stats.alerts_failed += 1
                error_msg = f"Unexpected error [{profile.name}] worker {worker_idx}: {e}"
                if len(self.stats.errors) < 100:
                    self.stats.errors.append(error_msg)
                Logger.logger.error(error_msg, exc_info=True)
                time.sleep(0.1)
            
            # Wait for next execution
            time.sleep(interval)
        
        Logger.logger.info(f"Alert sender [{profile.name}] worker {worker_idx} stopped")
    
    def _create_alert_payload(self, profile: BackendAlertProfile, cluster: str) -> dict:
        """
        Create runtime alert payload matching the node-agent's HTTP exporter format
        
        This mimics: func (e *HTTPExporter) createAlertPayload(...)
        """
        # Generate unique identifiers for this alert
        unique_id = uuid.uuid4().hex
        container_id = uuid.uuid4().hex
        pod_name = f"stress-pod-{random.randint(1000, 9999)}"
        workload_name = f"stress-deployment-{random.randint(1, 100)}"
        pid = random.randint(1000, 65535)
        
        # Create timestamp
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        
        # Build the RuntimeAlert structure
        alert = {
            "alertName": profile.alert_name,
            "arguments": {
                "syscall": profile.syscall
            },
            "infectedPID": pid,
            "md5Hash": uuid.uuid4().hex,
            "sha1Hash": uuid.uuid4().hex,
            "severity": profile.severity,
            "size": f"{random.randint(10, 500)} kB",
            "timestamp": timestamp,
            "uniqueID": unique_id,
            "profileMetadata": {
                "status": "completed",
                "completion": "complete",
                "name": f"replicaset-{workload_name}-{uuid.uuid4().hex[:8]}",
                "failOnProfile": True,
                "type": 0
            },
            "ruleDescription": f"{profile.alert_name}: {profile.syscall}",
            "malwareFile": {
                "hashes": {},
                "timestamps": {
                    "creationTime": "0001-01-01T00:00:00Z",
                    "modificationTime": "0001-01-01T00:00:00Z",
                    "accessTime": "0001-01-01T00:00:00Z"
                },
                "ownership": {},
                "attributes": {}
            },
            "processTree": {
                "processTree": {
                    "startTime": "0001-01-01T00:00:00Z"
                }
            },
            "signature": {
                "first_seen": "0001-01-01T00:00:00Z"
            },
            "kind": {"Group": "", "Version": "", "Kind": ""},
            "resource": {"Group": "", "Version": "", "Resource": ""},
            "clusterName": cluster,
            "containerName": f"stress-container-{random.randint(1, 100)}",
            "hostNetwork": False,
            "namespace": self.config.namespace,
            "nodeName": f"stress-node-{random.randint(1, 10)}",
            "containerID": container_id,
            "podName": pod_name,
            "podNamespace": self.config.namespace,
            "workloadName": workload_name,
            "workloadNamespace": self.config.namespace,
            "workloadKind": "Deployment",
            "cdrevent": {
                "cloudMetadata": {},
                "eventData": {}
            },
            "request": {},
            "response": {},
            "sourcePodInfo": {
                "clusterName": cluster
            },
            "networkscan": {},
            "alertType": 0,
            "alertSourcePlatform": 0,
            "ruleID": profile.rule_id,
            "hostName": "",
            "message": f"{profile.alert_name}: {profile.syscall}"
        }
        
        # Build the ProcessTree structure
        process_tree = {
            "processTree": {
                "pid": pid,
                "cmdline": f"stress-cmd-{uuid.uuid4().hex[:8]}",
                "comm": f"stress-comm-{uuid.uuid4().hex[:8]}",
                "ppid": random.randint(1, 999),
                "pcomm": "containerd-shim",
                "uid": 0,
                "gid": 0,
                "startTime": "0001-01-01T00:00:00Z",
                "cwd": "/app",
                "path": "/usr/local/bin/python3.10"
            },
            "containerID": container_id
        }
        
        # Build the final payload structure
        payload = {
            "kind": "RuntimeAlerts",
            "apiVersion": "kubescape.io/v1",
            "spec": {
                "alerts": [alert],
                "processTree": process_tree,
                "cloudMetadata": {
                    "provider": "digitalocean",
                    "instance_id": str(random.randint(100000000, 999999999)),
                    "instance_type": "s-2vcpu-4gb",
                    "region": "nyc1",
                    "private_ip": f"10.116.0.{random.randint(1, 254)}",
                    "public_ip": f"167.71.20.{random.randint(1, 254)}",
                    "hostname": f"pool-wn7zyztjc-smf{random.randint(100, 999)}"
                }
            }
        }
        
        return payload

    def _print_results(self):
        """Print final test results"""
        Logger.logger.info("\n" + "=" * 80)
        Logger.logger.info("BACKEND STRESS TEST RESULTS")
        Logger.logger.info("=" * 80)
        Logger.logger.info(f"Duration: {self.stats.duration_seconds():.1f} seconds")
        Logger.logger.info(f"Alerts sent: {self.stats.alerts_sent}")
        Logger.logger.info(f"Alerts failed: {self.stats.alerts_failed}")
        Logger.logger.info(f"Success rate: {self.stats.success_rate():.1f}%")
        Logger.logger.info(f"Average rate: {self.stats.alerts_per_second():.1f} alerts/second")
        
        expected = self.config.total_expected_alerts()
        actual = self.stats.alerts_sent
        Logger.logger.info(f"Expected alerts: {expected}")
        Logger.logger.info(f"Actual alerts: {actual} ({(actual/expected*100) if expected > 0 else 0:.1f}% of expected)")
        
        if self.stats.errors:
            Logger.logger.info(f"\nSample errors (showing first 10 of {len(self.stats.errors)}):")
            for i, error in enumerate(self.stats.errors[:10], 1):
                Logger.logger.info(f"  {i}. {error}")
        
        Logger.logger.info("=" * 80 + "\n")
    
    def cleanup(self, **kwargs):
        """Cleanup - stop any running threads and port-forward"""
        Logger.logger.info("Cleaning up backend stress test resources")
        
        # Stop alert generation threads
        self.is_running = False
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        # Teardown port-forward if it was set up
        self._teardown_port_forward()
        
        Logger.logger.info("Backend stress test cleanup completed")
        return super().cleanup(**kwargs)

