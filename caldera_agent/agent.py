"""
Provides Caldera Agent. Can be run as a script for testing.
"""

import asyncio
import logging
import os
import yaml
import pprint
import ssl

# !!!! Important, this is needed to prevent idna Exceptions in SOME cases
# https://github.com/pyinstaller/pyinstaller/issues/1113
# Do not delete this
import encodings.idna

from caldera_agent import async_client
from caldera_agent import agent_protocol
from caldera_agent import rest_api
from caldera_agent import interfaces

# Add module name to log messages
log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())
log.setLevel(logging.WARNING)


class CalderaAgent(object):
    def __init__(self):
        self.open_connections = {}  # this Dict tracks connected RATs ej. { RAT_PID: RAT_PROTOCOL_INSTANCE }
        self.loop = None  # Will be initialized with a reference to the main ProactorEventLoop()
        self.server = None  # Will be initialized with reference to server returned by agent_protocol.start_pipe_server
        self.agents_client = None
        self.log_levels = {'debug': logging.DEBUG, 'info': logging.INFO, 'warning': logging.WARNING,
                           'error': logging.ERROR, 'critical': logging.CRITICAL}
        self.conf = None
        self.conf_path = None
        self.interface = None
        self.caldera_server = None

    @staticmethod
    def close(loop):
        loop.call_soon_threadsafe(loop.stop)
        log.info("Exiting.")

    async def new_client_cb(self, protocol_instance):
        log.debug("New client: {}".format(protocol_instance.client_pid))
        self.open_connections[protocol_instance.client_pid] = protocol_instance
        await self.send_clients()

    async def lost_client_cb(self, protocol_instance):
        try:
            del self.open_connections[protocol_instance.client_pid]
            log.debug("Disconnect from implant: {}".format(protocol_instance.client_pid))
            await self.send_clients()
        except KeyError:
            log.debug("Disconnect from client not in open_connections.")

    async def send_clients(self):
        clients = self.interface.clients()
        await self.caldera_server.clients(clients=clients)

    def start(self, loop=None):
        if loop is not None:
            self.loop = loop
        else:
            self.loop = asyncio.ProactorEventLoop()
            loop = self.loop
            asyncio.set_event_loop(loop)
        # self.loop.set_debug(True)
        file_path = os.path.realpath(__file__)
        if file_path.endswith("pyc"):
            # This is necessary because when running as service caldera_agent.pyc is appended to cagent.exe's path
            self.conf_path = os.path.join(os.path.dirname(os.path.dirname(file_path)), "conf.yml")
        else:
            self.conf_path = os.path.join(os.path.dirname(file_path), "conf.yml")

        try:
            with open(self.conf_path, 'r') as f:
                self.conf = yaml.load(f.read())
        except FileNotFoundError:
            log.error("Exiting because configuration file was not located: '{}'".format(self.conf_path))
            return
        log.info('Initializing with:\n{}'.format(pprint.pformat(self.conf, indent=4)))

        # Change logging to user defined level
        log_level = self.conf.get('logging_level', 'info')
        logging.getLogger().setLevel(self.log_levels[log_level])
        log.info("Log level set to '{}'".format(log_level))

        # setup the ssl context
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cadata=self.conf['cert'])

        if not self.conf.get('verify_hostname', True):
            ssl_context.check_hostname = False

        token = self.conf.get('token', '')
        url_root = self.conf['url_root']

        self.caldera_server = rest_api.AsyncRequestAPI(ssl_context=ssl_context, token=token, url_root=url_root)

        # create an interface for the client
        self.interface = interfaces.LocalInterface(self.open_connections, self.caldera_server)

        self.agents_client = async_client.Client(self.interface, self.caldera_server)

        loop.create_task(self.send_clients())

        self.server = loop.create_task(agent_protocol.start_pipe_server(client_connected_cb=self.new_client_cb,
                                                                        client_disconnected_cb=self.lost_client_cb,
                                                                        loop=loop))

        loop.create_task(self.agents_client.run_forever(long_poll=True))
        loop.create_task(self.agents_client.heartbeat())
        loop.run_forever()

        # todo close agents_client and pipeserver
        loop.close()


if __name__ == '__main__':
    # Use this logging level until the logging level specified in conf.yml is loaded.
    logging.basicConfig(level=logging.DEBUG)
    CalderaAgent().start()
