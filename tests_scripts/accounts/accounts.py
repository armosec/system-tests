
from systest_utils import Logger, statics
from tests_scripts.helm.base_helm import BaseHelm




class Accounts(BaseHelm):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)


        self.helm_kwargs = {
            "capabilities.vulnerabilityScan": "disable",
            "grypeOfflineDB.enabled": "false",
            "capabilities.relevancy": "disabled",
            "capabilities.runtimeObservability": "disable",
            "capabilities.malwareDetection": "disable",
            "capabilities.runtimeDetection": "disable",
            "alertCRD.installDefault": False,
            "alertCRD.scopeClustered": False,
        }
        test_helm_kwargs = self.test_obj.get_arg("helm_kwargs")
        if test_helm_kwargs:
            self.helm_kwargs.update(test_helm_kwargs)

        self.fw_name = None
        self.cluster = None
        self.wait_for_agg_to_end = False


    def start(self):
        """
        Agenda:
        1. Install kubescape with helm-chart
        2. Validate accounts kubernetes list.
        3. Validate accounts kubernetes uniquevalues.
        4. Create bad arn cloud account with cspm.
        5. Create good arn cloud account with cspm.
        6. Validate accounts cloud with cspm list.
        7. Validate accounts cloud with cspm uniquevalues.
        8. Edit cloud account with cspm.
        9. validate cloud account after edit.
        10. Delete cloud account with cspm.
        11. Validate cloud account after delete.
        """

        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'
        self.cluster, self.namespace = self.setup(apply_services=False)

        Logger.logger.info('Stage 1: Install kubescape with helm-chart')
        self.install_kubescape(helm_kwargs=self.helm_kwargs)

        Logger.logger.info('Stage 2: Validate accounts kubernetes list')
        self.validate_accounts_kubernetes_list(self.cluster)
        

        return self.cleanup()
    

    def cleanup(self, **kwargs):
        return super().cleanup(**kwargs)
    

    def install_kubescape(self, helm_kwargs: dict = None):
        self.add_and_upgrade_armo_to_repo()
        self.install_armo_helm_chart(helm_kwargs=helm_kwargs)
        self.verify_running_pods(namespace=statics.CA_NAMESPACE_FROM_HELM_NAME)
    

    def validate_accounts_kubernetes_list(self, cluster:str):
        """
        Validate accounts kubernetes list.
        """

        body = {
            "pageSize": 100,
            "pageNum": 1,
            "innerFilters": [{
                "cluster": cluster
            }]
        }

        r, t = self.wait_for_report(
            self.backend.get_kubernetes_accounts, 
            timeout=180,
            body=body
            )

        assert "response" in r, f"response not in {r}"
        assert len(r["response"]) > 0, f"response is empty"
        assert r["response"][0]["cluster"] == cluster, f"cluster is not {cluster}"
    
