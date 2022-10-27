import io
import time


class AgentLog(object):
    """
    Cyber Armor Agent log message.
    """

    def __init__(self, pid, level, message):
        super(AgentLog, self).__init__()
        self.pid = pid
        self.level = level
        self.message = message.split('\n')[0]

    def __str__(self):
        return '{} - {}: {}'.format(self.pid, self.level, self.message)

    def get_pid(self):
        return self.pid


class AgentLogParser(object):
    """
    Cyber Armor Agent logs extractor and parser.
    """

    def __init__(self, container=None, stream=None, i_str=None):
        super(AgentLogParser, self).__init__()

        if len({container, stream, i_str}) > 2:
            raise Exception(
                'Only exactly one input parameter should be provided.')

        self.container = None
        if container:
            self.container = container
        elif stream:
            self.raw_stream = stream
        elif i_str:
            self.raw_stream = io.StringIO(i_str)
        else:
            raise Exception('No input parameter was provided.')

        self.errors = list()
        self.debugs = list()
        self.infos = list()
        self.all = list()
        self.warnings = list()
        self.has_agent = False

        g = super(AgentLogParser, self).__getattribute__
        self._levels = {
            "DEBUG": g('debugs'),
            "INFO": g('infos'),
            "WARNING": g('warnings'),
            "ERROR": g('errors')
        }

    def __getattribute__(self, attr):
        g = super(AgentLogParser, self).__getattribute__
        if attr in ('debugs', 'infos', 'warnings', 'errors', 'all', 'has_agent'):
            g('_parse')()
        return g(attr)

    def _parse(self, raw_stream=None):
        g = super(AgentLogParser, self).__getattribute__

        if raw_stream:
            self.raw_stream = raw_stream
        elif g('container'):
            g('errors').__init__()
            g('debugs').__init__()
            g('infos').__init__()
            g('all').__init__()
            g('warnings').__init__()
            self.raw_stream = io.StringIO(self.container.logs(stdout=True, stderr=True).decode())

        for line in g('raw_stream'):
            if type(line) is bytes:
                line = line.decode()

            if not g('has_agent') and ('caa start returns 0' in line or
                                       (("withdll.exe:   with `" in line or 'after CAA run' in line) and ('cyberarmor.dll' in line))):
                self.__setattr__('has_agent', True)

            for level in g('_levels'):
                if '- {}: '.format(level) in line:
                    self.__setattr__('has_agent', True)
                    level_str = '- {}: '.format(level)
                    pid = ''.join(line[:line.find(level_str)].split())
                    pid = int(pid[-1]) if pid else ''
                    message = AgentLog(
                        pid, level, line[line.find(level_str) + len(level_str):])
                    g('all').append(message)
                    g('_levels')[level].append(message)

    def add_input(self, stream=None, i_str=None):
        if stream and i_str:
            raise Exception(
                'Only exactly one input parameter should be provided.')
        elif stream:
            stram = stream
        elif i_str:
            stream = io.StringIO(i_str)
        else:
            raise Exception('No input parameter was provided.')
        self._parse()
        self._parse(stream)

    def is_agent_loaded(self):
        if self.is_string_in_container(string='caa start returns 0', max_wait_time=2):
            return True
        return False

    def is_string_in_container(self, string, max_wait_time=5):
        start = time.time()
        logs = self.container.logs(stdout=True, stderr=True, stream=True)
        while time.time() - start < 60 * max_wait_time:
            try:
                if string in logs.next().decode():
                    return True
            except Exception as ex:
                time.sleep(1)
        return False
