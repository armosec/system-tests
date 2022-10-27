from tests_scripts import base_test
from systest_utils import Logger, statics


class CleanUpCustomer(base_test.BaseTest):
    def start(self):
        full_overview, content_length = self.backend.get_full_customer_overview()
        Logger.logger.warning(
            f"Full WLs overview({content_length},{len(full_overview)}): {full_overview}")
        for wlid in full_overview:
            Logger.logger.info(f"removing workload overview: {wlid}")
            try:
                res = self.backend.remove_microservice_data(wlid=wlid)
                Logger.logger.info(f"removing workload overview result: {res}")
            except Exception as ex:
                Logger.logger.error(f"removing workload overview failed")

        full_overview, content_length = self.backend.get_full_clusters_list()
        Logger.logger.warning(
            f"Full clusters overview({content_length}, {len(full_overview)}): {full_overview}")
        for cluster in full_overview:
            Logger.logger.info(f"removing cluster: {cluster}")
            try:
                res = self.backend.delete_ca_cluster(ca_cluster=cluster)
                Logger.logger.info(f"removing cluster result: {res}")
            except Exception as ex:
                Logger.logger.error(f"removing cluster failed")

        return statics.SUCCESS, ""
