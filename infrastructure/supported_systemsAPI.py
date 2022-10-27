import json
import time
from builtins import BaseException
from random import randint
from traceback import format_exc
from urllib.parse import parse_qs, urlparse

import boto3
import botocore
import elasticsearch
import hdfs
import psycopg2
import pymysql
import redis
import requests
from mechanize import Browser
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from wordpress_xmlrpc import Client, WordPressPost
from wordpress_xmlrpc.methods.posts import DeletePost, GetPost, NewPost

from systest_utils import Logger
from systest_utils.statics import FAILURE, SUCCESS
from systest_utils.systests_utilities import TestUtil


# Note: Not all the classes has tested.

class BaseSystem(object):
    """
    All Supported Systems Tests API should inharit
    """

    def __init__(self, host='127.0.0.1', port=None, user='user', pwd='1234', ssl=False, first=None):
        super(BaseSystem, self).__init__()
        prot = "https" if ssl else "http"
        if not port:
            port = 443 if ssl else 80
        self.base_url = "{prot}://{host}:{port}".format(
            prot=prot, host=host, port=port)
        self.host = host
        self.port = port
        self.user = user
        self.pwd = pwd
        self.ssl = ssl
        self.client = None
        if first:
            self.setup()
        else:
            self.connect()

    def __del__(self):
        self.close()

    def setup(self):
        # Optional for sites like WordPress. Drupal, etc.
        pass

    def connect(self):
        pass

    def insert(self, content):
        pass

    def retrieve(self, c_id):
        pass

    def remove(self, c_id):
        pass

    def close(self):
        pass

    def __repr__(self):
        return super(BaseSystem, self).__repr__()[:-1] + ' host={} port={}>'.format(self.host, self.port)


class WikiJS(BaseSystem):
    first = True

    def __init__(self, host="127.0.0.1", port=80, user='aa@bb.cc', pwd='abc123',
                 ssl=False, first=None):
        super(WikiJS, self).__init__(host, port, user, pwd,
                                     ssl, first=first if first else WikiJS.first)
        WikiJS.first = False
        self.jw_token: str = None

    def setup(self):
        finalize_data = {"adminEmail": self.user, "adminPassword": self.pwd,
                         "adminPasswordConfirm": self.pwd, "telemetry": False,
                         "siteUrl": self.base_url}
        res = requests.post(self.base_url + "/finalize",
                            json=finalize_data)
        assert res.status_code == 200 and res.json()["ok"], "Failed to register wikijs: {}, {}".format(
            res.status_code, res.content)
        TestUtil.sleep(30, "after finalizing")

    def connect(self):
        login_data = [{"operationName": None,
                       "variables": {"username": self.user, "password": self.pwd, "strategy": "local"},
                       "extensions": {},
                       "query": "mutation ($username: String!, $password: String!, $strategy: String!) {\n  authentication {\n    login(username: $username, password: $password, strategy: $strategy) {\n      responseResult {\n        succeeded\n        errorCode\n        slug\n        message\n        __typename\n      }\n      jwt\n      mustChangePwd\n      mustProvideTFA\n      mustSetupTFA\n      continuationToken\n      redirect\n      tfaQRImage\n      __typename\n    }\n    __typename\n  }\n}\n"}]
        res = requests.post(self.base_url + "/graphql", json=login_data)
        assert res.status_code == 200, "Failed to login to wikijs: {}, {}".format(
            res.status_code, res.content)
        res_json = res.json()
        resp_result = res_json[0]["data"]["authentication"]["login"]["responseResult"]
        assert resp_result["succeeded"] == True and resp_result["slug"] == "ok" and resp_result[
            "message"] == "Login success" and resp_result["errorCode"] == 0, "login to wikijs failed: {}".format(
            res_json)
        self.jw_token = res_json[0]["data"]["authentication"]["login"]["jwt"]

    def insert(self, content):
        if self.jw_token is None:
            self.connect()
        # return SUCCESS, 10
        desired_content_len = 70
        while len(content) < desired_content_len:
            content = content + content
        if len(content) > desired_content_len:
            content = content[:desired_content_len]
        insert_template = [{"operationName": None,
                            "variables": {"content": "# ARMO1 HELLO\nYour content here\n" + content, "description": "",
                                          "editor": "markdown", "locale": "en", "isPrivate": False, "isPublished": True,
                                          "path": "home" + content[:7], "publishEndDate": "", "publishStartDate": "",
                                          "scriptCss": "", "scriptJs": "", "tags": [], "title": "ARMO1"},
                            "extensions": {},
                            "query": "mutation ($content: String!, $description: String!, $editor: String!, $isPrivate: Boolean!, $isPublished: Boolean!, $locale: String!, $path: String!, $publishEndDate: Date, $publishStartDate: Date, $scriptCss: String, $scriptJs: String, $tags: [String]!, $title: String!) {\n  pages {\n    create(content: $content, description: $description, editor: $editor, isPrivate: $isPrivate, isPublished: $isPublished, locale: $locale, path: $path, publishEndDate: $publishEndDate, publishStartDate: $publishStartDate, scriptCss: $scriptCss, scriptJs: $scriptJs, tags: $tags, title: $title) {\n      responseResult {\n        succeeded\n        errorCode\n        slug\n        message\n        __typename\n      }\n      page {\n        id\n        updatedAt\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n"}]
        res = requests.post(self.base_url + "/graphql", json=insert_template, cookies={
            "jwt": self.jw_token}, headers={"Authorization": "Bearer " + self.jw_token})
        assert res.status_code == 200, "Failed to insert to wikijs: {}, {}".format(res.status_code, res.content)
        res_json = res.json()
        assert res_json, f"something went wrong, no json result received from insert command. text response: {res.text}"

        try:
            resp_result = res_json[0]["data"]["pages"]["create"]["responseResult"]
            page_id = res_json[0]["data"]["pages"]["create"]["page"]["id"]
        except:
            raise Exception(f"error inserting, insert result: {res_json}")
        assert resp_result["succeeded"] and resp_result["slug"] == "ok" and resp_result[
            "message"] == "Page created successfully." and resp_result[
                   "errorCode"] == 0, "login to wikijs failed: {}".format(res_json)
        return SUCCESS, page_id

    def retrieve(self, c_id):
        return None

    def remove(self, c_id):
        return SUCCESS

    def close(self):
        pass


class WordPress(BaseSystem):
    """docstring for WordPress"""
    first = True

    def __init__(self, host="127.0.0.1", port=80, user='root', pwd='123456', ssl=False, first=None):
        super(WordPress, self).__init__(host, port, user, pwd,
                                        ssl, first=first if first else WordPress.first)
        WordPress.first = False

    def connect(self):
        err = ''
        for i in range(4):
            try:
                self.client = Client(
                    "{}/xmlrpc.php".format(self.base_url), self.user, self.pwd)
                return
            except BaseException as e:
                err = format_exc()
                Logger.logger.error(
                    'host: {}, port: {}, user: {}, pwd: {}'.format(self.base_url, self.port, self.user, self.pwd))
                Logger.logger.error(e)
        raise Exception(err)

    def setup(self):
        url = '{}/wp-admin/install.php'.format(self.base_url)
        # step 1
        code = ''
        for i in range(4):
            try:
                r = requests.post(
                    url, params={"step": 1}, timeout=10, data={"language": ""})
                code = r.status_code
                if code == 200:
                    break
            except Exception as ex:
                Logger.logger.error(ex)
                code = format_exc()
            time.sleep(3)
        assert (code == 200), "WordPress Setup step one received message: {}".format(
            code)
        self.cookies = r.cookies

        # step 2
        data = dict()
        data["weblog_title"] = "test"
        data["user_name"] = self.user
        data["admin_password"] = self.pwd
        data["pass1-text"] = self.pwd
        data["admin_password2"] = self.pwd
        data["pw_weak"] = "on"
        data["admin_email"] = "test@test.run"
        data["blog_public"] = 1
        data["Submit"] = "Install+WordPress"
        data["language"] = ''
        for i in range(4):
            try:
                r = requests.post(
                    r.url, params={"step": 2}, timeout=10, data=data, cookies=r.cookies)
                code = r.status_code
                if code == 200:
                    self.cookies = r.cookies
                    return
            except Exception as ex:
                Logger.logger.error(ex)
                code = format_exc()
            time.sleep(4)
        raise Exception(
            "WordPress Setup step two received message: {}".format(code))

    def insert(self, content="content " * 9):
        post = WordPressPost()
        post.title = content[len(content) - 6:]
        post.content = content
        post.terms_names = {
            'post_tag': [content[len(content) - 3:], 'firstpost'],
            'category': [content[len(content) - 4:], 'Tests']
        }
        err = ''
        for i in range(4):
            try:
                p_id = self.client.call(NewPost(post))
                return SUCCESS, p_id
            except:
                err = format_exc()
                time.sleep(3)
                self.connect()
        raise Exception(err)

    def retrieve(self, p_id):
        for i in range(4):
            try:
                rslt = self.client.call(GetPost(p_id)).content
                return rslt
            except Exception as ex:
                Logger.logger.error(ex)
        return None

    def remove(self, p_id):
        return self.client.call(DeletePost(p_id))


class Scality(BaseSystem):
    """docstring for Scality"""
    first = True

    def __init__(self, host='0.0.0.0', port=8000, user='accessKey1', pwd='verySecretKey1', ssl=False, first=None):
        self.bucket_name = "test-backet"
        super(Scality, self).__init__(host, port, user, pwd,
                                      ssl, first=first if first else Scality.first)
        Scality.first = False

    def setup(self):
        self.connect()
        self.client.create_bucket(Bucket=self.bucket_name)

    def connect(self):
        self.client = boto3.resource('s3', aws_access_key_id=self.user,
                                     aws_secret_access_key=self.pwd,
                                     endpoint_url=self.base_url,
                                     config=botocore.client.Config(connect_timeout=10, retries={'max_attempts': 3}))

    def insert(self, content="content " * 9):
        c_id = Randomy.random_id()
        for i in range(10):
            try: 
                self.client.Object(self.bucket_name, '{}.txt'.format(c_id)).put(Body=content)
                break
            except Exception as e:
                time.sleep(1)
                print(e)
                if i == 9:
                    raise e
        return SUCCESS, c_id

    def retrieve(self, c_id):
        return self.client.Object(self.bucket_name, '{}.txt'.format(c_id)).get()['Body'].read()

    def remove(self, c_id):
        self.client.Object(self.bucket_name, '{}.txt'.format(c_id)).delete()
        return SUCCESS


class Redis(BaseSystem):
    """docstring for Redis"""
    first = True

    def __init__(self, host='127.0.0.1', port=6379, user='', pwd='', ssl=False, first=None):
        super(Redis, self).__init__(host, port, user, pwd,
                                    ssl, first=first if first else Redis.first)
        Redis.first = False

    def setup(self):
        self.connect()

    def connect(self):
        self.client = redis.Redis(host=self.host, port=self.port)

    def insert(self, content="content " * 9):
        try:
            self.connect()
        except:
            pass
        c_id = Randomy.random_id()
        self.client.set(str(c_id), content)
        return SUCCESS, c_id

    def retrieve(self, c_id):
        try:
            self.connect()
        except:
            pass
        try:
            ret = self.client.get(str(c_id)).decode()
        except BaseException as e:
            raise ValueError('Cant read data! reason: {}'.format(e))

        return ret

    def remove(self, c_id):
        return self.client.delete(str(c_id))


class Elasticsearch(BaseSystem):
    """docstring for Elasticsearch"""
    first = True

    def __init__(self, host='0.0.0.0', port=9200, user=None, pwd=None, ssl=False, first=None):
        super(Elasticsearch, self).__init__(host, port, user, pwd,
                                            ssl, first=first if first else Elasticsearch.first)
        Elasticsearch.first = False

    def setup(self):
        self.connect()

    def connect(self):
        self.client = elasticsearch.Elasticsearch(self.base_url)

    def insert(self, content="content " * 9):
        return_val = (FAILURE, 0)
        for i in range(3):
            try:
                res = self.client.index(
                    index="test-index", doc_type='tweet', body={'text': content})
                if res['_shards']["failed"] == 0:
                    return SUCCESS, res['_id']
            except Exception as ex:
                Logger.logger.error(ex)
                return_val = (FAILURE, "3 tries failed: {}".format(ex))
        return return_val

    def retrieve(self, c_id):
        for i in range(3):
            try:
                return self.client.get(index="test-index", doc_type='tweet', id=c_id)['_source']['text']
            except:
                pass
        raise Exception("Cant read data from db")

    def remove(self, c_id):
        res = self.client.delete(index="test-index", doc_type='tweet', id=c_id, wait_for_active_shards='all', params={"request_timeout": 20})
        a = SUCCESS if res['_shards']["successful"] == res['_shards']["total"] else FAILURE
        if a == FAILURE:
            print("elasticsearch remove {}".format(res))
        return a


class Hadoop(BaseSystem):
    """docstring for Hadoop"""
    first = True

    def __init__(self, host='127.0.0.1', port=50070, user=None, pwd=None, ssl=False, first=None):
        super(Hadoop, self).__init__(host, port, user, pwd,
                                     ssl, first=first if first else Hadoop.first)
        Hadoop.first = False

    def setup(self):
        self.connect()

    def connect(self):
        self.client = hdfs.Client(self.base_url)

    def insert(self, content="content " * 9):
        c_id = Randomy.random_id()
        self.client.write(hdfs_path="/new_file{}".format(c_id), data=content)
        return SUCCESS, c_id

    def retrieve(self, c_id):
        with self.client.read('/new_file{}'.format(c_id)) as fil:
            ret = fil.read()
        return ret

    def remove(self, c_id):
        self.client.delete('/new_file{}'.format(c_id))


class Mongo(BaseSystem):
    """docstring for Mongo"""
    first = True

    def __init__(self, host='127.0.0.1', port=27017, user=None, pwd=None, ssl=False, first=None):
        super(Mongo, self).__init__(host, port, user, pwd,
                                    ssl, first=first if first else Mongo.first)
        Mongo.first = False

    def setup(self):
        self.connect()

    def connect(self):
        from pymongo import MongoClient
        db = MongoClient(host=self.host, port=self.port)
        self.client = db.test_db

    def insert(self, content="content " * 9):
        c_id = Randomy.random_id()
        r = self.client.something.insert_one({'_id': c_id, 'text': content})
        return (SUCCESS, c_id) if r else (FAILURE, None)

    def retrieve(self, c_id):
        return self.client.something.find_one({'_id': c_id})['text']

    def remove(self, c_id):
        self.retrieve(c_id)
        self.client.something.delete_one({'_id': c_id})
        try:
            self.retrieve(c_id)
            assert False, 'Could not remove id {} properly'.format(c_id)
        except AssertionError as e:
            raise (e)
        except:
            pass
        return SUCCESS


class Mysql(BaseSystem):
    """docstring for Mysql"""
    first = True

    def __init__(self, host='0.0.0.0', port=3306, user='root', pwd='123456', ssl=False, first=None, db_name='systest'):
        self.db_name = db_name
        super(Mysql, self).__init__(host, port, user, pwd,
                                    ssl, first=first if first else Mysql.first)
        Mysql.first = False
        self.connect()

    def __del__(self):
        self.close()

    def connect(self):
        err = ''
        for i in range(4):
            try:
                self.client = pymysql.connect(host=self.host, port=self.port, user=self.user, password=self.pwd,
                                              database=self.db_name)
                return
            except:
                err = format_exc()
            time.sleep(3)
        raise Exception(err)

    def setup(self):
        try:
            self.client = pymysql.connect(
                host=self.host, port=self.port, user=self.user, password=self.pwd)
        except Exception as e:
            raise Exception("in Mysql.setup, pymysql.connect, {}".format(e))
        try:
            self._create_db()
        except Exception as e:
            raise Exception("in Mysql.setup, _create_db, {}".format(e))
        try:
            self._use_db()
        except Exception as e:
            raise Exception("in Mysql.setup, _use_db, {}".format(e))
        try:
            self._create_table()
        except Exception as e:
            raise Exception("in Mysql.setup, _create_table, {}".format(e))

    def _create_db(self):
        with self.client.cursor() as cursor:
            cursor.execute('CREATE DATABASE {}'.format(self.db_name))
            self.client.commit()

    def _use_db(self):
        with self.client.cursor() as cursor:
            cursor.execute('use {}'.format(self.db_name))
            self.client.commit()

    def _create_table(self, name_size='({})'.format(1024 ** 3)):
        with self.client.cursor() as cursor:
            cursor.execute(
                'CREATE TABLE CUSTOMERS(ID VARCHAR (255) NOT NULL, NAME TEXT {} NOT NULL, PRIMARY KEY (ID))'.format(
                    name_size))
            self.client.commit()

    def insert(self, content="content " * 9):
        err = ''
        for i in range(4):
            try:
                c_id = Randomy.random_id()
                with self.client.cursor() as cursor:
                    cursor.execute(
                        'INSERT INTO CUSTOMERS (ID, NAME) VALUES (%s, %s)', (str(c_id), content))
                    self.client.commit()
                return SUCCESS, c_id
            except:
                err = format_exc()
                time.sleep(3)
        raise Exception(err)

    def retrieve(self, c_id):
        err = ''
        for i in range(2):
            try:
                with self.client.cursor() as cursor:
                    cursor.execute(
                        "SELECT NAME FROM CUSTOMERS WHERE ID = '{}'".format(str(c_id)))
                    result = cursor.fetchone()
                    assert result, 'ID {} not found!'.format(c_id)
                return result[0]
            except:
                err = format_exc()
                time.sleep(3)

        raise Exception(err)

    def remove(self, c_id):
        with self.client.cursor() as cursor:
            cursor.execute(
                "DELETE FROM CUSTOMERS WHERE ID = '{}'".format(str(c_id)))
            self.client.commit()
        try:
            self.retrieve(c_id)
            raise Exception('Could not remove id {} properly'.format(c_id))
        except Exception:
            pass

        return SUCCESS

    def close(self):
        try:
            self.client.close()
        except:
            pass


class Postgress(Mysql):
    """docstring for Postgress"""
    first = True

    def __init__(self, host='0.0.0.0', port=5432, user='postgres', pwd='123456', ssl=False, first=None,
                 db_name='postgres'):
        super(Postgress, self).__init__(host=host, port=port, user=user, pwd=pwd, ssl=ssl, db_name=db_name,
                                        first=first if first else Postgress.first)
        self.db_name = db_name
        Postgress.first = False

    def __del__(self):
        pass

    def setup(self):
        self.connect()
        self._create_table('')

    def connect(self, timeout=300):
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                self.client = psycopg2.connect(host=self.host,
                                               port=self.port,
                                               user=self.user,
                                               password=self.pwd,
                                               database=self.db_name)
                break
            except:
                pass
            time.sleep(2)
        self.client.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)

    def insert(self, content="content " * 9):
        c_id = Randomy.random_id()
        with self.client.cursor() as cursor:
            cursor.execute(
                'INSERT INTO POST (ID, NAME) VALUES (%s, %s)', (str(c_id), content))
            self.client.commit()
        return SUCCESS, c_id

    def _create_table(self, name_size='({})'.format(1024 ** 3)):
        with self.client.cursor() as cursor:
            cursor.execute(
                'CREATE TABLE POST (ID VARCHAR (255) NOT NULL, NAME TEXT {} NOT NULL, PRIMARY KEY (ID))'.format(
                    name_size))
            self.client.commit()

    def retrieve(self, c_id):
        try:
            with self.client.cursor() as cursor:
                cursor.execute(
                    "SELECT NAME FROM POST WHERE ID = '{}'".format(str(c_id)))
                result = cursor.fetchone()
                assert result, 'ID {} not found!'.format(c_id)
        except:
            self.connect()
            with self.client.cursor() as cursor:
                cursor.execute(
                    "SELECT NAME FROM POST WHERE ID = '{}'".format(str(c_id)))
                result = cursor.fetchone()
                assert result, 'ID {} not found!'.format(c_id)

        return result[0]

    def remove(self, c_id):
        try:
            self.connect()
        except:
            pass
        with self.client.cursor() as cursor:
            cursor.execute(
                "DELETE FROM POST WHERE ID = '{}'".format(str(c_id)))
            self.client.commit()
        try:
            self.retrieve(c_id)
            raise Exception('Could not remove id {} properly'.format(c_id))
        except AssertionError:
            pass

        return SUCCESS


class Joomla(BaseSystem):
    """docstring for Joomla"""
    first = True

    def __init__(self, db_info: dict, host='0.0.0.0', port=80, user='root', pwd='123456', ssl=False, first=None):
        """
        db_info: like - {"host":hostname, 'type': database_type, 'user': username, 'pwd':pwd}
            possible db types: 'mysqli', 'pgsql', 'pdomysql', 'postgresql'. 'mysqli' is used for common mysql.
        """
        assert db_info, "db_info parameters are missing"
        self.db_info = db_info
        super(Joomla, self).__init__(host, port, user, pwd,
                                     ssl, first=first if first else Joomla.first)
        Joomla.first = False

    def setup(self):
        b = Browser()
        b.open(self.base_url)
        try:
            # Joomla settings
            b.select_form(id="adminForm")
            b.form["jform[site_name]"] = 'Test Runner Site'
            b.form["jform[admin_email]"] = 'test@test.cyberarmor'
            b.form["jform[admin_user]"] = self.user
            b.form["jform[admin_password]"] = str(self.pwd)
            b.form["jform[admin_password2]"] = str(self.pwd)
            b.submit()
            assert not json.loads(b.response().get_data().decode())["error"]

            # Database settings
            b.open(
                "{}/installation/index.php?tmpl=body&view=database".format(self.base_url), timeout=10)
            b.select_form(id='adminForm')
            b.form["jform[db_type]"] = [self.db_info["type"]]
            b.form["jform[db_host]"] = self.db_info["host"]
            b.form["jform[db_user]"] = self.db_info["user"]
            b.form["jform[db_pass]"] = self.db_info["pwd"]
            b.form["jform[db_name]"] = 'joomla test db{}'.format(
                Randomy.random_id())
            b.form["jform[db_prefix]"] = 'tbpre{}_'.format(randint(0, 300))
            b.submit()
            # assertion
            ret = b.response().get_data().decode()
            assert ret.startswith('{'), ret
            ret = json.loads(ret)
            assert not ret["error"], ret['messages']

            # Summery
            b.open(
                "{}/installation/index.php?tmpl=body&view=summary".format(self.base_url), timeout=10)
            b.select_form(id='adminForm')
            b.form["jform[sample_file]"] = ["sample_blog.sql"]
            b.submit()
            # assertion
            ret = b.response().get_data().decode()
            assert ret.startswith('{'), ret
            ret = json.loads(ret)
            assert not ret["error"], ret['messages']

            # Install
            b.open(
                "{}/installation/index.php?tmpl=body&view=install".format(self.base_url), timeout=10)
            b.select_form(id='adminForm')
            b.form.action = "{}/installation/index.php?task=InstallDatabase_backup".format(
                self.base_url)
            b.submit()
            # assertion
            ret = b.response().get_data().decode()
            assert ret.startswith('{'), ret
            ret = json.loads(ret)
            assert not ret["error"], ret['messages']

            b.open(
                "{}/installation/index.php?tmpl=body&view=install".format(self.base_url), timeout=10)
            b.select_form(id='adminForm')
            b.form.action = "{}/installation/index.php?task=InstallDatabase".format(
                self.base_url)
            b.submit()
            # assertion
            ret = b.response().get_data().decode()
            assert ret.startswith('{'), ret
            ret = json.loads(ret)
            assert not ret["error"], ret['messages']

            b.open(
                "{}/installation/index.php?tmpl=body&view=install".format(self.base_url), timeout=10)
            b.select_form(id='adminForm')
            b.form.action = "{}/installation/index.php?task=InstallConfig".format(
                self.base_url)
            b.submit()
            # assertion
            ret = b.response().get_data().decode()
            assert ret.startswith('{'), ret
            ret = json.loads(ret)
            assert not ret["error"], ret['messages']

            b.open(
                "{}/installation/index.php?tmpl=body&view=complete".format(self.base_url), timeout=10)
            b.select_form(id='adminForm')
            b.form.action = "{}/installation/index.php?task=removefolder".format(
                self.base_url)
            b.submit()
            # assertion
            ret = b.response().get_data().decode()
            assert ret.startswith('{'), ret
            ret = json.loads(ret)
            assert not ret["error"], ret['messages']
        except BaseException as e:
            raise Exception(
                "Error in Joomla automatic installation. reason: {}".format(e))
        self.client = b
        self.connect()

    def connect(self):
        try:
            if not self.client:
                self.client = Browser()
            # self.client.clear_history()
            self.client.set_handle_robots(False)
            self.client.open("{}/administrator/".format(self.base_url))
            self.client.select_form(id="form-login")
            self.client.form["username"] = self.user
            self.client.form["passwd"] = self.pwd
            self.client.submit()
            self.client.open(
                "{}/administrator/index.php".format(self.base_url), timeout=10)
        except Exception as e:
            Logger.logger.error(e)
            raise Exception(e)

    def insert(self, content="content " * 9):
        # try:
        #     self.connect()
        # except:
        #     pass

        self.client.open(
            "{}/administrator/index.php".format(self.base_url), timeout=10)
        lnk = self.client.find_link(
            url="/administrator/index.php?option=com_content&task=article.add")
        self.client.follow_link(lnk)
        self.client.select_form(id="item-form")
        self.client.form.set_all_readonly(False)
        self.client.form["jform[title]"] = "Test Runner Article"
        self.client.form["jform[articletext]"] = "<p>{}</p>".format(content)
        self.client.form['task'] = "article.apply"
        self.client.form['jform[state]'] = ['1']
        self.client.form['jform[catid]'] = ['2']
        self.client.form['jform[featured]'] = ['1']
        self.client.form['jform[access]'] = ['1']
        self.client.submit()

        query_str = parse_qs(urlparse(self.client.geturl()).query)
        if 'id' in query_str:
            return SUCCESS, query_str['id'][0]

    def retrieve(self, c_id):
        err = None
        for i in range(3):
            try:
                r = self.client.open("{}/index.php?option=com_content&view=article&id={}".format(self.base_url, c_id),
                                     timeout=10)
                return r.get_data().decode()
            except Exception as e:
                Logger.logger.error(e)
                err = e

            time.sleep(3)
        raise Exception(err) if err is not None else Exception(
            "In retrieve - Unknown exception")

    def remove(self, c_id):
        try:
            self.client.open("{}/administrator/index.php?option=com_content&view=articles".format(self.base_url),
                             timeout=10)
            self.client.select_form(id='adminForm')
            self.client.form.set_all_readonly(False)
            self.client.form["cid[]"] = [str(c_id)]
            self.client.form["task"] = "articles.trash"
            self.client.submit()
        except Exception as e:
            Logger.logger.warning(e)
        return SUCCESS


class Drupal(BaseSystem):
    """docstring for Drupal"""
    first = True

    def __init__(self, host, port=80, user='user', pwd='1234', ssl=False, first=None, db_info={}):
        """
        db_info: like - {"host":hostname, 'port':port 'type': database_type, 'user': username, 'pwd':pwd}
            possible db types: 'sqlite', 'mysql', 'pgsql'. 'mysql' is used for common mysql.
        """
        assert ((not first) or db_info), "db_info parameter is missing"
        self.db_info = db_info
        super(Drupal, self).__init__(host, port, user, pwd,
                                     ssl, first=first if first else Drupal.first)
        Drupal.first = False

    def setup(self):
        b = Browser()

        # Select language
        b.set_handle_robots(False)
        b.open(self.base_url)
        b.select_form(id='install-select-language-form')
        b.submit()

        # Select profile
        b.select_form(id="install-select-profile-form")
        b.form['profile'] = ['demo_umami']
        b.submit()

        # Set db
        db_type = self.db_info['type']
        b.select_form(id='install-settings-form')
        b.form['driver'] = [db_type]
        b.form['{}[database]'.format(db_type)] = 'test'
        b.form['{}[prefix]'.format(db_type)] = 'tbpre{}_'.format(
            randint(0, 300))
        if db_type != 'sqlite':
            b.form['{}[username]'.format(db_type)] = self.db_info['user']
            b.form['{}[password]'.format(db_type)] = self.db_info['pwd']
            b.form['{}[host]'.format(db_type)] = self.db_info['host']
            b.form['{}[port]'.format(db_type)] = str(self.db_info['port'])
        b.submit()

        # install
        b.follow_link(b.links()[0])
        magic = '<div class="progress__percentage">'
        percents = '0'
        while percents != '100':
            b.reload()
            percents = b.response().get_data().decode()
            assert magic in percents, 'Some error occure'
            percents = percents[(percents.find(magic) + len(magic)):]
            percents = percents[:percents.find('%')]

        # Configure
        b.open('{}/core/install.php?rewrite=ok&langcode=en&profile=demo_umami'.format(
            self.base_url))  # id="install-configure-form"
        b.select_form(id='install-configure-form')
        b.form['site_mail'] = "test@test.run"
        b.form['account[mail]'] = "test@test.run"
        b.form['account[name]'] = self.user
        b.form['account[pass][pass1]'] = str(self.pwd)
        b.form['account[pass][pass2]'] = str(self.pwd)
        b.submit()

        self.client = b
        self.connect()

    def connect(self):
        self.client = Browser()
        self.client.set_handle_robots(False)
        self.client.clear_history()
        self.client.open('{}/user/login'.format(self.base_url))
        self.client.select_form(id='user-login-form')
        self.client.form['name'] = self.user
        self.client.form['pass'] = self.pwd
        self.client.submit()

    def insert(self, content="content " * 9):
        self.client.open('{}/node/add/page'.format(self.base_url))
        self.client.select_form(id='node-page-form')
        self.client.form['title[0][value]'] = 'Test Runner Article'
        self.client.form['body[0][value]'] = '<p>{}</p>'.format(content)
        self.client.form['moderation_state[0][state]'] = ['published']
        self.client.submit()

        return SUCCESS, self.client.geturl().split('/')[-1]

    def retrieve(self, c_id):
        self.client.open('{}/node/{}'.format(self.base_url, c_id))

        return self.client.response().get_data().decode()

    def remove(self, c_id):
        # try:
        #     self.connect()
        # except:
        #     pass
        self.client.open(
            '{}/node/{}/delete?destination=/admin/content'.format(self.base_url, c_id))
        self.client.select_form(id='node-page-delete-form')
        self.client.submit()
        return SUCCESS


class Randomy(object):
    """docstring for Randomy"""

    @staticmethod
    def random_string(lenght=2):
        out = ''
        char_range = "QWERTYUIOPASDFGHJKLZXCVBNMMqwertyuiopasdfghjklzxcvbnm1234567890"
        char_len = len(char_range)
        for i in range(lenght):
            out += char_range[randint(0, char_len - 1)]
        return out

    @staticmethod
    def random_id():
        return randint(1, 1000000000000000)
