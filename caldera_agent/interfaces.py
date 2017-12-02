import asyncio
import logging
from caldera_agent import agent_protocol
from caldera_agent import foster3 as foster
from caldera_agent import utils
import win32ts
import win32security
import re


# Add module name to log messages
log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())
log.setLevel(logging.WARNING)


class Interface(object):
    def __init__(self, open_connections, server_api):
        self.open_connections = open_connections
        self.server_api = server_api

    async def run(self, action, args):
        raise NotImplementedError()

    def clients(self):
        raise NotImplementedError()


class NoClientError(Exception):
    pass


class InterfaceError(Exception):
    pass


class LocalInterface(Interface):
    def clients(self):
        # return objects that represent commanders
        return [{'pid': x,
                 'elevated': self.open_connections[x].is_elevated,
                 'executable_path': self.open_connections[x].executable_path,
                 'username': self.open_connections[x].user_name} for x in self.open_connections.keys()]

    async def _implant(self, function, pid, params: dict):  # runs in implant
        # pid = int(args.pop(0))  # pid at beginning of list
        if pid not in self.open_connections:
            raise NoClientError()

        return_params = await self.open_connections[pid].run_function(function, params)
        log.debug("implant received : '{}'".format(return_params))
        return return_params

    async def run(self, action, args):
        status = False
        try:
            if action == 'execute':
                output = await self._run_in_caldera_subprocess(args['command_line'])
                status = True
            elif action == 'clients':
                output = self.clients()
                status = True
            elif action == 'write_commander':
                output = await self._write_commander(args['path'])
                status = True
            elif action == 'rats':
                pattern = re.compile(r'\[\[[-.\w]*\]\]')
                if 'function' in args:
                    parameters = args.get('parameters', {})
                    for key, val in parameters.items():
                        matches = re.findall(pattern, val)
                        for match in list(set(matches)):
                            filler = await self.server_api.get_macro(match[2:-2])
                            fill_string = filler.decode()
                            parameters[key] = val.replace(match, fill_string)

                    pid = int(args.get('name'))
                    output = await self._implant(args['function'], pid, parameters)
                    status = True
                else:
                    output = "{'action': 'rats'} must contain a 'function'."
            elif action == 'create_process':
                output = self._create_process(args['process_args'], parent=args.get('parent', None),
                                              hide=args.get('hide', True), output=args.get('output', False))
                status = True
            elif action == 'create_process_as_user':
                output = self._create_process_as_user(args['process_args'], args['user_domain'],
                                                      args['user_name'], args['user_pass'],
                                                      parent=args.get('parent', None), hide=args.get('hide', True),
                                                      output=args.get('output', False))
                status = True
            elif action == 'create_process_as_active_user':
                output = self._create_process_as_active_user(args['process_args'], parent=args.get('parent', None),
                                                             hide=args.get('hide', True), output=args.get('output', False))
                status = True
            else:
                output = "'{}' is not a recognized action.".format(action)
        except agent_protocol.DisconnectedError:
            output = "Rat crashed during execution"

        return status, output

    async def _write_commander(self, path):
        # download commander
        commander = await self.server_api.get_commander()

        # TODO could use ThreadPoolExecutor here for better performance
        with open(path, 'wb') as f:
            f.write(commander)

        return await self._run_in_caldera_subprocess("takeown /F {} /A".format(path))

    async def _run_in_caldera_subprocess(self, cmd_str=None):
        if cmd_str is None:
            raise InterfaceError('LocalInterface._run_in_caldera_subprocess called with no cmd_args')
        # Runs shell commands
        proc = await asyncio.create_subprocess_shell(cmd_str, stdout=asyncio.subprocess.PIPE,
                                                     stderr=asyncio.subprocess.STDOUT)
        stdout, _ = await proc.communicate()
        return stdout.decode()

    def _create_process_as_user(self, process_args, user_domain, user_name, user_pass, parent=None, hide=True,
                                output=False):
        hUser = win32security.LogonUser(user_name, user_domain, user_pass, win32security.LOGON32_LOGON_INTERACTIVE,
                                        win32security.LOGON32_PROVIDER_DEFAULT)
        return self._create_process(process_args, user_handle=hUser.handle, parent=parent, hide=hide, output=output)

    def _create_process_as_active_user(self, process_args, parent=None, hide=True, output=False):
        WTS_CURRENT_SERVER_HANDLE = 0
        sessions = win32ts.WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE)
        log.debug('{}'.format(sessions))
        active_session = None
        for session in sessions:
            if session['State'] == utils.WTS_CONNECTSTATE_CLASS.WTSActive:
                active_session = session
                break
        if active_session is None:
            raise Exception("Could not find an active session")
        # active_session = win32ts.WTSGetActiveConsoleSessionId()
        log.debug("Active Session is: {}".format(active_session))
        hUser = win32ts.WTSQueryUserToken(active_session['SessionId'])
        return self._create_process(process_args, user_handle=hUser.handle, parent=parent, hide=hide, output=output)

    def _create_process(self, process_args, user_handle=None, parent=None, hide=True, output=False):
        if parent:
            PROCESS_CREATE_PROCESS = 0x80
            PROCESS_DUP_HANDLE = 0x40
            handle = utils.get_process_handle(parent, PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE)
            parent = handle.handle
        else:
            parent = None

        stdout = None
        stderr = None
        if output:
            stdout = foster.PIPE
            stderr = foster.STDOUT

        process = foster.Popen(process_args, hide=hide, user_token=user_handle, parent=parent, stdout=stdout, stderr=stderr)
        if output:
            stdout, stderr = process.communicate()
            if stdout:
                return stdout.decode()
            else:
                return ""
        return process.pid
