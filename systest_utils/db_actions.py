import datetime
import time
from multiprocessing import Value
from random import randint

from systest_utils import TestUtil, Logger, statics

ONE_MB = 1000000  # bytes
MAX_MEMORY = 5000000000  # bytes


class DataBaseActions(object):
    def __init__(self, db, host, create_db, db_args: dict):
        self.total_memory_sent = Value('f', 0)
        self.total_memory_removed = Value('f', 0)

        # m = Manager()
        self.id_list = list()

        # create db
        Logger.logger.info("setup database")
        self.db = db(host=host, first=create_db, **db_args)

    def call_insert(self):
        random_number_of_mb = randint(ONE_MB // 32, ONE_MB // 16)

        text = TestUtil.random_string(random_number_of_mb)
        status, i_id = self.db.insert(content=text)
        if status == statics.FAILURE:
            raise Exception("Some error occurred. can not insert to db: {}".format(i_id))
        if i_id == "0":
            return

        self.total_memory_sent.value += len(text)
        self.id_list.append((i_id, text[:25], len(text)))

    def call_remove(self):
        if len(self.id_list) < 10:
            return
        i_id, _, size = self.id_list.pop(randint(0, len(self.id_list) - 1))
        status = self.db.remove(i_id)
        if status == statics.FAILURE:
            raise Exception("Some error occurred. can not remove from db. id: {}".format(i_id))
        self.total_memory_removed.value += size

    def call_retrieve(self):
        i_id = self.id_list[randint(0, len(self.id_list) - 1)]
        try:
            self.db.retrieve(i_id[0])
        except Exception as e:
            Logger.logger.error("call_retrieve failed. err: {}, id: {}".format(e, i_id))
            raise Exception(e)

    @staticmethod
    def db_basic_actions(db, host: str, db_args: dict, create_db: bool = True, duration: int = 1):
        """
        perform basic actions

        * configure a database/application
        * perform basic actions as insert/read/delete for a desired time period

        :param db: the database or web application
        :param db_args: additional db setup arguments
        :param create_db: default true. use False flag if the database/table was created (gradual encryption/decryption tests)
        :param host: db host
        :param duration: test duration, will sleep or perform insert/read/delete actions on the db
        :return:
        """

        # configure db and trigger db actions
        db_actions = DataBaseActions(db=db, host=host, create_db=create_db, db_args=db_args)

        start = time.time()
        Logger.logger.debug(
            "running simple operations on database for {} minutes".format(datetime.timedelta(seconds=duration)))
        while duration > time.time() - start:
            db_actions.call_insert()
            db_actions.call_retrieve()
            if randint(0, 1) and randint(0, 1):  # randomly remove from db. the possibility should n be 50%
                db_actions.call_remove()
            time.sleep(randint(0, 3))
