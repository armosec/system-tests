import os

from systest_utils import TestUtil


class Credentials(object):
    def __init__(self, customer: str, name: str, password: str, client_id: str, secret_key: str):
        self.customer = customer
        self.name = name
        self.password = password
        self.client_id = client_id
        self.secret_key = secret_key

    def get_name(self):
        return self.name

    def get_password(self):
        return self.password

    def get_customer(self):
        return self.customer

    def get_client_id(self):
        return self.client_id

    def get_secret_key(self):
        return self.secret_key


def set_credentials():
    credentials_file_path = os.getenv("credentials_file_path")
    if credentials_file_path:
        return set_credentials_from_file(path=credentials_file_path)
    customer = os.getenv("CUSTOMER")
    if not customer:
        raise Exception("Fail to get customer from environment variables")
    name = os.getenv("USERNAME")
    if not name:
        raise Exception("Fail to get name from environment variables")
    password = os.getenv("PASSWORD")
    if not password:
        raise Exception("Fail to get password from environment variables")
    client_id = os.getenv("CLIENT_ID")
    secret_key = os.getenv("SECRET_KEY")

    if not client_id or not secret_key:
        client_id = secret_key = ''

    return Credentials(customer=customer, name=name, password=password, client_id=client_id, secret_key=secret_key)


def set_credentials_from_file(path: str):
    config_data = TestUtil.json_file_to_dict("", path)

    if "customer" not in config_data.keys():
        raise Exception("Fail to get customer from config_data file")
    customer = config_data["customer"]

    if "name" not in config_data.keys():
        raise Exception("Fail to get name from config_data file")
    name = config_data["name"]

    if "password" not in config_data.keys():
        raise Exception("Fail to get password from config_data file")
    password = config_data["password"]

    client_id = config_data.get("client_id", "")
    secret_key = config_data.get("secret_key", "")

    return Credentials(customer=customer, name=name, password=password, client_id=client_id, secret_key=secret_key)


CREDENTIALS = set_credentials()
