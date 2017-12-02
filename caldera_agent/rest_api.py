import asyncio
import logging
import sys
import win32api
import win32con
import traceback
import urllib.request
import urllib.parse
import concurrent
import socket
import json as json_module
from socket import getfqdn
from urllib.error import URLError
from caldera_agent import utils as caldera_utils

# Add module name to log messages
log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())
log.setLevel(logging.WARNING)


class RequestFailed(Exception):
    def __init__(self, status, reason):
        self.status = status
        self.reason = reason
        super(RequestFailed, self).__init__()


class ServerApi(object):
    def __init__(self, url_root, reconnect=5, token=None):
        self.root = url_root
        self._headers = {'CONTENT-TYPE': 'application/json'}
        self._cookies = {}
        if token:
            self._cookies['AUTH'] = token
        self.queues = {}
        self.reconnect = reconnect

    async def start(self, uri):
        queue = self.queues[uri]
        while not queue.empty():
            future, coroutine = await queue.get()
            try:
                future.set_result((True, (await coroutine)))
            except:
                if future.cancelled():
                    log.error("Caught an exception when trying to run a coroutine and the future was canceled so "
                              "it cannot be returned: {}".format(traceback.format_exc()))
                else:
                    future.set_result((False, sys.exc_info()))

        del self.queues[uri]

    async def api(self, uri, json, method='GET', **kwargs):
        """ Override this method with a method that performs the request to the server."""
        raise NotImplementedError()

    @staticmethod
    def _build_login_token(hostname, dns_domain, windows_domain, fqdn):
        return {'agent': True,
                'hostname': hostname,
                'dns_domain': dns_domain,
                'windows_domain': windows_domain,
                'fqdn': fqdn}

    async def rest(self, uri, item=None, delete=False, **kwargs):
        res = None
        last_error_type = None
        last_error_args = tuple()
        while not res:
            try:
                res = await self._raw_rest(uri, item, delete, **kwargs)
                if last_error_type is not None:
                    log.warning("Connection re-established")
                    last_error_type = None
                    last_error_args = tuple()
            except (WindowsError, URLError) as e:
                if isinstance(e, URLError):
                    e = e.reason
                if isinstance(e, WindowsError):
                    if last_error_type != type(e) or last_error_args != e.args:
                        # we haven't already logged this failure
                        last_error_type = type(e)
                        last_error_args = e.args
                        log.warning('Could not connect to server: {}'.format(e.strerror))
                else:
                    log.error('Unrecognized error when connecting to server: {}'.format(traceback.format_exc()))
                await asyncio.sleep(self.reconnect)
        return res

    async def _raw_rest(self, uri, item=None, delete=False, **kwargs):
        if uri not in self.queues:
            self.queues[uri] = asyncio.Queue()
            asyncio.get_event_loop().create_task(self.start(uri))
        # push requests on a queue to enforce single ordering
        future = asyncio.Future()
        coroutine = self._rest(uri, item, delete, **kwargs)
        await self.queues[uri].put((future, coroutine))
        await future
        success, result = future.result()
        if success:
            return result
        else:
            raise result[1].with_traceback(result[2])

    async def _rest(self, uri, item=None, delete=False, **kwargs):
        # Both set to None for then GET root
        key = kwargs.pop('id', None)
        method = 'GET'
        if isinstance(item, dict):
            key = item.get('_id', key)
        if key is not None:
            uri += '/' + key
            if item is not None:
                method = 'PUT'
        elif item is not None:
            method = 'POST'

        if delete is True:
            method = 'DELETE'

        # If no id set but object is set, 'POST' to root
        response = await self.api(uri, item, method=method, **kwargs)
        log.debug('{}: {}'.format(method, response.url))
        if response.status == 403:
            fqdn = getfqdn()
            hostname = fqdn.split('.')[0]
            dns_domain = win32api.GetComputerNameEx(win32con.ComputerNameDnsDomain)
            windows_domain = caldera_utils.getDomainNameFlat()

            token = await self._get_token(hostname, dns_domain, windows_domain, fqdn, self._rest)

            # renegotiate access token
            log.debug('renegotiated authentication token')
            self._cookies['AUTH'] = token
            response = await self.api(uri, item, method=method, **kwargs)
        elif response.status != 200:
            reason = ""
            try:
                reason = response.reason
            except AttributeError:
                log.warning("Got a response with no reason: {}".format(response.status))
            raise RequestFailed(response.status, reason)
        return response

    async def agents(self, agent=None, **kwargs):
        resp = await self.rest('/api/agents', item=agent, **kwargs)
        return resp.json()

    async def networks(self, network=None, **kwargs):
        resp = await self.rest('/api/networks', item=network, **kwargs)
        return resp.json()

    async def hosts(self, network, host=None, **kwargs):
        uri = '/api/networks/{}/hosts'.format(network['_id'])
        resp = await self.rest(uri, item=host, **kwargs)
        return resp.json()

    async def commands(self, network, host, command=None, **kwargs):
        uri = '/api/networks/{}/hosts/{}/commands'.format(network['_id'], host['_id'])
        resp = await self.rest(uri, item=command, **kwargs)
        return resp.json()

    async def jobs(self, job=None, **kwargs):
        resp = await self.rest('/api/jobs', item=job, **kwargs)
        return resp.json()

    async def operations(self, operation=None, **kwargs):
        resp = await self.rest('/api/operations', item=operation, **kwargs)
        return resp.json()

    async def clients(self, clients=None, **kwargs):
        await self.rest('/api/clients', item=clients, **kwargs)

    async def get_token(self, hostname, dns_domain, windows_domain, fqdn):
        return (await self._get_token(hostname, dns_domain, windows_domain, fqdn, self.rest))

    async def _get_token(self, hostname, dns_domain, windows_domain, fqdn, rest):
        login_token = self._build_login_token(hostname, dns_domain, windows_domain, fqdn)
        retval = await rest('/login', item=login_token)
        return retval.content.decode('utf8')

    async def get_commander(self):
        retval = await self.rest('/commander')
        return retval.content

    async def get_macro(self, macro):
        retval = await self.rest('/macro/' + macro)
        return retval.content

    async def stay_alive(self):
        await self.rest('/api/heartbeat')
        return True


class AsyncRequestAPI(ServerApi):
    def __init__(self, url_root, token=None, ssl_context=None):
        super().__init__(url_root, token=token)
        self.ssl_context = ssl_context
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)

    async def api(self, uri, json, method='GET', **kwargs):
        response = None
        timeout = 60.0

        if 'params' in kwargs:
            uri += '?' + urllib.parse.urlencode(kwargs['params'])
        headers = dict(self._headers)
        for k, v in self._cookies.items():
            headers['COOKIE'] = '{}={}'.format(k, v)
        data = json_module.dumps(json)

        while response is None:
            req = urllib.request.Request(self.root + uri, data=data.encode('utf8'), headers=headers, method=method)

            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(self.executor, self.urlread, req, self.ssl_context, timeout)
        return response

    # note this function is run in a thread, so it should be very careful about any shared state
    @staticmethod
    def urlread(req, ssl_context, timeout):
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ssl_context) as s:
                return APIResponse(s.code, s.read(), s.url)
        except socket.timeout:
            return None
        except urllib.error.HTTPError as e:
            return APIResponse(e.code, e.read(), e.url)


class APIResponse(object):
    def __init__(self, status, content, url):
        self.status = status
        self.content = content
        self._json = None
        self.url = url

    def json(self):
        if self._json:
            return self._json

        return json_module.loads(self.content.decode('utf8'))
