#
# wekalogging - a streamlined, common logging setup
#
import logging
import logging.handlers
import platform

DEFAULT = "default"
MODULES = dict()

def register_module(module_name, logging_level):
    MODULES[module_name] = logging_level


def configure_logging(logger, verbosity):
    loglevel = logging.INFO  # default logging level
    libloglevel = logging.ERROR

    # default message formats
    console_format = "%(message)s"
    # syslog_format =  "%(levelname)s:%(message)s"

    syslog_format = "%(process)s:%(filename)s:%(lineno)s:%(funcName)s():%(levelname)s:%(message)s"

    if verbosity == 1:
        loglevel = logging.INFO
        console_format = "%(levelname)s:%(message)s"
        syslog_format = "%(process)s:%(filename)s:%(lineno)s:%(funcName)s():%(levelname)s:%(message)s"
        libloglevel = logging.INFO
    elif verbosity == 2:
        loglevel = logging.DEBUG
        console_format = "%(filename)s:%(lineno)s:%(funcName)s():%(levelname)s:%(message)s"
        syslog_format = "%(process)s:%(filename)s:%(lineno)s:%(funcName)s():%(levelname)s:%(message)s"
    elif verbosity > 2:
        loglevel = logging.DEBUG
        console_format = "%(filename)s:%(lineno)s:%(funcName)s():%(levelname)s:%(message)s"
        syslog_format = "%(process)s:%(filename)s:%(lineno)s:%(funcName)s():%(levelname)s:%(message)s"
        libloglevel = logging.DEBUG

    # create handler to log to console
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(console_format))
    logger.addHandler(console_handler)

    # create handler to log to syslog
    logger.info(f"setting syslog on {platform.platform()}")
    if platform.platform()[:5] == "macOS":
        syslogaddr = "/var/run/syslog"
    else:
        syslogaddr = "/dev/log"
    syslog_handler = logging.handlers.SysLogHandler(facility=logging.handlers.SysLogHandler.LOG_DAEMON, address=syslogaddr)

    # add syslog handler to root logger
    if syslog_handler is not None:
        syslog_handler.setFormatter(logging.Formatter(syslog_format))
        logger.addHandler(syslog_handler)

    # set default loglevel
    logger.setLevel(loglevel)

    # configure registered modules
    for module, level in MODULES.items():
        if level == DEFAULT:
            logging.getLogger(module).setLevel(loglevel)
        else:
            logging.getLogger(module).setLevel(level)