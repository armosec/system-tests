from websocket import create_connection,WebSocket

class ThreadSignal(object):
    def __init__(self):
        super().__init__()
        self._terminate = False

    def if_terminate(self):
        return self._terminate

    def terminate(self):
        self._terminate = True

class WebsocketWrapper():
    def __init__(self):
        self._connection:WebSocket = None
        self._reconnect: bool = True

    def connect(self, host):
        self._connection = create_connection(url=host)
        self._reconnect: bool=True

    def close(self):
        if self._connection:
            self._connection.close()
        self._reconnect = False

    def reconnect(self):
        return self._reconnect

    def is_connected(self):
        return self._connection.connected

    def recv(self):
        return self._connection.recv()
