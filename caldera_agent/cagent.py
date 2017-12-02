import win32serviceutil
import win32service
import servicemanager
import logging
import logging.handlers
import asyncio
import sys
import os
import agent


class WinSvcLogHandler(logging.Handler):
    """ Custom logging handler used to send logging messages to the event log when run as a service. """
    def __init__(self):  # 0 = NOTSET
        servicemanager.LogInfoMsg("Created WinSvcLogHandler")
        self.svc_event_loggers = {logging.CRITICAL: servicemanager.LogErrorMsg,
                                  logging.ERROR: servicemanager.LogErrorMsg,
                                  # logging.WARNING: servicemanager.LogWarningMsg,
                                  # logging.INFO: servicemanager.LogInfoMsg,
                                  }
        super(WinSvcLogHandler, self).__init__()

    def emit(self, record):
        formatted = self.format(record)
        if formatted:
            if record.levelno in self.svc_event_loggers:
                self.svc_event_loggers[record.levelno](formatted[:4096])
        else:
            self.svc_event_loggers.get(record.levelno, servicemanager.LogInfoMsg)("Bad: there was an error logging a message")


class AppServerSvc(win32serviceutil.ServiceFramework):
    """ Create a New Service by inheriting ServiceFramework. This class definition contains just the
    adjustments needed to accommodate running CalderaAgent as a service. The actual CalderaAgent code is mixed in"""
    _svc_name_ = "cagent"
    _svc_display_name_ = "Caldera Agent Service"
    current_event_loop = None  # This is needed because the Service Framework is implemented in its own thread,
    # asyncio.get_event_loop retrieves the event loop from the current active thread.

    def __init__(self, args):
        if 'debug' not in sys.argv:  # If started as installed service do not write out to console.
            devnull = open(os.devnull, 'w')
            sys.stderr = devnull
            sys.stdout = devnull
        else:
            # set console to read WCHARs
            # _setmode(_fileno(stdout), _O_WTEXT);
            from msvcrt import setmode as _setmode
            _O_WTEXT = 0x00020000
            _setmode(sys.stdout.fileno(), _O_WTEXT)

        # Start Logging (Log to Windows Event Log) - Logging starts as DEBUG; user defined logging level is loaded
        # from conf.yml when CalderaAgent.start() is called.
        logging.basicConfig(handlers=(WinSvcLogHandler(),), level=logging.DEBUG)

        logging.debug("cagent argv is: {}".format(sys.argv))
        logging.debug("cagent file realpath is: {}".format(os.path.realpath(__file__)))

        self.loop = None
        self.caldera_agent = agent.CalderaAgent()
        win32serviceutil.ServiceFramework.__init__(self, args)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.caldera_agent.close(self.loop)

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        self.main()

    def main(self):
        self.loop = asyncio.ProactorEventLoop()
        loop = self.loop
        asyncio.set_event_loop(loop)
        self.caldera_agent.start(loop=loop)


global return_message

if __name__ == '__main__':
    # For running as a Python script.
    win32serviceutil.HandleCommandLine(AppServerSvc)
    return_message = None


def HandleCommandLine():
    win32serviceutil.HandleCommandLine(AppServerSvc)
    return_message = None
