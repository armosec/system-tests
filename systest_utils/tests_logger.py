# encoding: utf-8
import logging
import os
import sys
from logging import WARNING, DEBUG
from time import gmtime, strftime


class OverridePythonLogger(logging.Logger):
    def success(self, msg, *args, **kwargs):
        """
        Log 'msg % args' with severity 'DEBUG'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.debug("Houston, we have a %s", "thorny problem", exc_info=1)
        """
        SUCCESS = 21
        logging.addLevelName(SUCCESS, 'SUCCESS')
        if self.isEnabledFor(SUCCESS):
            self._log(SUCCESS, msg, args, **kwargs)

    def test(self, msg, *args, **kwargs):
        """
        Log 'msg % args' with severity 'DEBUG'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.debug("Houston, we have a %s", "thorny problem", exc_info=1)
        """
        test_level = 11
        logging.addLevelName(test_level, 'TEST')
        if self.isEnabledFor(test_level):
            self._log(test_level, msg, args, **kwargs)

    def todo(self, msg, *args, **kwargs):
        """
        Log 'msg % args' with severity 'DEBUG'.

        To pass exception information, use the keyword argument exc_info with
        a true value, e.g.

        logger.debug("Houston, we have a %s", "thorny problem", exc_info=1)
        """
        test_level = 12
        logging.addLevelName(test_level, 'TODO')
        if self.isEnabledFor(test_level):
            self._log(test_level, msg, args, **kwargs)


class Logger(object):
    logger = OverridePythonLogger(__name__)
    formatter = None

    @staticmethod
    def set_logger(logging_level=DEBUG, name:str=""):
        base_path = os.path.dirname(os.path.realpath(__file__))
        os.makedirs(os.path.join(base_path, 'logger'), exist_ok=True)

        file_name = os.path.join(base_path, 'logger', '{}{}.log'.format(name, strftime("%Y-%m-%d_%H-%M-%S", gmtime())))

        Logger.formatter = Logger.set_formatter()
        Logger.logger.setLevel(logging_level)

        file_log_handler = logging.FileHandler(file_name)
        file_log_handler.setLevel(DEBUG)
        file_log_handler.setFormatter(Logger.formatter)
        Logger.logger.addHandler(file_log_handler)

    @staticmethod
    def add_stream(stream=sys.stderr, level=logging.ERROR):
        s = logging.StreamHandler(stream)
        s.setLevel(level)
        Logger.logger.addHandler(s)
        s.setFormatter(Logger.formatter)
        return s

    @staticmethod
    def remove_stream(s):
        Logger.logger.removeHandler(s)

    # @staticmethod
    # def set_formatter():
    #     # nice output format
    #     format = '[%(levelname)-5s] - %(asctime)16s, %(filename)-16s: %(funcName)-16s - %(message)-16s'
    #     date_format = '%H:%M:%S %d-%m-%Y'
    #     try:
    #         import colorlog
    #     except ImportError:
    #         Logger.logger.info("Cant find colorlog, printing without colors!")
    #     if 'colorlog' in sys.modules and os.isatty(2):
    #         cformat = '%(log_color)s' + format
    #         formatter = colorlog.ColoredFormatter(cformat, date_format,
    #                                               log_colors={'DEBUG': 'reset', 'INFO': 'cyan',
    #                                                           'WARNING': 'bold_yellow', 'ERROR': 'bold_red',
    #                                                           'CRITICAL': 'bold_red', 'SUCCESS': 'green'})
    #     else:
    #         formatter = logging.Formatter(format, date_format)
    #     return formatter

    @staticmethod
    def set_formatter():
        # nice output format
        format = '%(levelname)-8s %(asctime)16s %(filename)s:%(lineno)d %(funcName)16s: %(message)-16s'
        date_format = '%H:%M:%S %d-%m-%Y'
        try:
            import colorlog
        except ImportError:
            Logger.logger.info("Cant find colorlog, printing without colors!")
        if 'colorlog' in sys.modules and os.isatty(2):
            cformat = '%(log_color)s' + format
            formatter = colorlog.ColoredFormatter(cformat, date_format,
                                                  log_colors={'DEBUG': 'reset', 'INFO': 'cyan',
                                                              'WARNING': 'bold_yellow', 'ERROR': 'bold_red',
                                                              'CRITICAL': 'bold_red', 'SUCCESS': 'green'})
        else:
            formatter = logging.Formatter(format, date_format)
        return formatter

    @staticmethod
    def get_file_location():
        return Logger.logger.handlers[0].baseFilename

    @staticmethod
    def get_logger_by_level(level: str):
        logger_by_level = {"debug": Logger.logger.debug,
                           "info": Logger.logger.info,
                           "warning": Logger.logger.warning,
                           "error": Logger.logger.error,
                           "success": Logger.logger.success}

        return logger_by_level[level.lower()] if level.lower() in logger_by_level else logger_by_level["debug"]
