
from systest_utils import Logger, statics
from tests_scripts.helm.base_helm import BaseHelm




class Clusters(BaseHelm):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)


        self.helm_kwargs = {
            "capabilities.runtimeObservability": "disable",
            "capabilities.networkPolicyService": "disable",
            "capabilities.seccompProfileService": "disable",
            "capabilities.nodeProfileService": "disable",
            "capabilities.vulnerabilityScan": "disable",
            "grypeOfflineDB.enabled": "false",
            "capabilities.relevancy": "disabled",
            "capabilities.malwareDetection": "disable",
            "capabilities.runtimeDetection": "disable",
            "alertCRD.installDefault": False,
            "alertCRD.scopeClustered": False,
        }
        test_helm_kwargs = self.test_obj.get_arg("helm_kwargs")
        if test_helm_kwargs:
            self.helm_kwargs.update(test_helm_kwargs)

        self.wait_for_agg_to_end = False


    def start(self):
        """
        Agenda:
        1. Install kubescape with helm-chart
        2. Validate accounts kubernetes list
        3. Validate accounts kubernetes uniquevalues
        TODO: verify nodes and cpus reported for cluster
        """
         
        self.cluster, self.namespace = self.setup(apply_services=False)

        
        Logger.logger.info('1. Install kubescape with helm-chart')
        self.install_kubescape(helm_kwargs=self.helm_kwargs)

        Logger.logger.info('2. Validate accounts kubernetes list')

        r, t = self.wait_for_report(
            self.validate_accounts_kubernetes_list, 
            timeout=180,
            cluster=self.cluster
        )

        Logger.logger.info('3. Validate accounts kubernetes uniquevalues')
        self.validate_accounts_kubernetes_uniquevalues(cluster=self.cluster)

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

        res = self.backend.get_kubernetes_accounts(body=body)

     

        assert "response" in res, f"response not in {res}"
        assert len(res["response"]) > 0, f"response is empty"
        assert res["response"][0]["cluster"] == cluster, f"cluster is not {cluster}"

    def validate_accounts_kubernetes_uniquevalues(self, cluster:str):
        """
        Validate accounts kubernetes uniquevalues.
        """

        unique_values_body = {
            "fields": {
                "cluster": cluster,
            },
            "innerFilters": [
                {
                "cluster": cluster
                }
            ],
            "pageSize": 100,
            "pageNum": 1
            }
        
        res = self.backend.get_kubernetes_accounts_uniquevalues(body=unique_values_body)
        assert "fields" in res, f"failed to get fields for kubernetes accounts unique values, body used: {unique_values_body}, res is {res}"
        assert len(res["fields"]) > 0, f"response is empty"
        assert len(res["fields"]["cluster"]) == 1, f"response is empty"
        assert res["fields"]["cluster"][0] == cluster, f"cluster is not {cluster}"