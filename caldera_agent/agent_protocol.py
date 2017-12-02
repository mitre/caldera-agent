import asyncio
import win32pipe
import win32security
import win32file
import _winapi
import win32api
import logging
import ntsecuritycon
from asyncio import windows_utils
from enum import Enum
from caldera_agent import agent_encoder, PIPE_PATH
from caldera_agent import utils as caldera_utils
from collections import OrderedDict

# Add module name to log messages
log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())
log.setLevel(logging.WARNING)


# this is required because the default implementation does not reject remote clients and does not allow
# un-elevated clients write access when the pipe server is started by an Administrator or SYSTEM.
def monkey_patch_pipe_server():
    def _server_pipe_handle(self, first):
        # Return a wrapper for a new pipe handle.
        try:
            if self.closed():
                return None
        except AttributeError:
            if self._address is None:
                return None

        # Create a new SECURITY_ATTRIBUTES object to open up write permissions to non-elevated clients.
        # Get the SID of this process' owner to add to the new DACL
        owner_sid = win32security.GetTokenInformation(win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), win32security.TOKEN_QUERY), win32security.TokenOwner)

        # Build the new ACL -- SYSTEM, built-in Administrators and the Owner get full control (like default)
        acl = win32security.ACL()  # Default buffer size of 64 OK
        acl.AddAccessAllowedAce(win32file.FILE_ALL_ACCESS,
                                win32security.CreateWellKnownSid(win32security.WinLocalSystemSid))
        acl.AddAccessAllowedAce(win32file.FILE_ALL_ACCESS,
                                win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid))
        acl.AddAccessAllowedAce(win32file.FILE_ALL_ACCESS, owner_sid)

        # Allow all Users to both Read and Write to the pipe:
        # See http://stackoverflow.com/questions/29947524/c-let-user-process-write-to-local-system-named-pipe-custom-security-descrip
        acl.AddAccessAllowedAce(ntsecuritycon.FILE_GENERIC_READ | ntsecuritycon.FILE_WRITE_DATA,
                                win32security.CreateWellKnownSid(win32security.WinBuiltinUsersSid))

        # Construct new SECUIRTY_ATTRIBUTES AND SECURITY_DESCRIPTOR objects
        new_sa = win32security.SECURITY_ATTRIBUTES()
        new_sd = win32security.SECURITY_DESCRIPTOR()

        # Add the ACL to the SECURITY_DESCRIPTOR:
        new_sd.SetDacl(True, acl, False)

        # Add the SECURITY_DESCRIPTOR to the SECURITY_ATTRIBUTES object and set the Inheritance flag
        new_sa.SECURITY_DESCRIPTOR = new_sd
        new_sa.bInheritHandle = False

        PIPE_REJECT_REMOTE_CLIENTS = 0x8
        flags = _winapi.PIPE_ACCESS_DUPLEX | _winapi.FILE_FLAG_OVERLAPPED
        if first:
            flags |= _winapi.FILE_FLAG_FIRST_PIPE_INSTANCE

        py_pipe = win32pipe.CreateNamedPipe(self._address, flags,
                          win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE |
                          win32pipe.PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                          win32pipe.PIPE_UNLIMITED_INSTANCES,
                          windows_utils.BUFSIZE, windows_utils.BUFSIZE,
                          win32pipe.NMPWAIT_WAIT_FOREVER, new_sa)

        # Extract the handle number from the PyHandle Object and pass it the Aysncio PipeHandle constructor
        pipe = windows_utils.PipeHandle(py_pipe.handle)

        # IMPORTANT: Detach the handle from the PyHandle object so it is not auto-closed when py_pipe is destroyed!
        py_pipe.Detach()

        self._free_instances.add(pipe)

        return pipe

    asyncio.windows_events.PipeServer._server_pipe_handle = _server_pipe_handle


async def start_pipe_server(client_connected_cb=None, client_disconnected_cb=None, loop=None):
    """
    :param client_connected_cb: Called when a client connects. Used for keeping track of active connections.
    :param client_disconnected_cb: Called when a client disconnects. Used for keeping track of active connections.
    :param loop: The event loop the server will run on. If None, get_event_loop is called and the default loop is used.
    :param reject_remote_clients: If True, monkey patches the server to prevent access to pipe via smb.
    :return: Returns a server object.
    """
    monkey_patch_pipe_server()

    if loop is None:
        loop = asyncio.ProactorEventLoop()
        asyncio.set_event_loop(loop)

    def factory():  # client_connected_cb=None, client_disconnected_cb=None, loop=None
        protocol = AgentProtocol(client_connected_cb=client_connected_cb,
                                 client_disconnected_cb=client_disconnected_cb,
                                 loop=loop)
        return protocol
    return await loop.start_serving_pipe(factory, PIPE_PATH)


class DisconnectedError(Exception):
    pass


class ClientState(Enum):
    Unknown = 0
    Connected = 1
    Implant = 2
    Gone = 3


class AgentProtocol(asyncio.Protocol):
    def __init__(self, client_connected_cb=None, client_disconnected_cb=None, loop=None):
        self.buf = []
        self.response_queue = asyncio.Queue()
        self.responses = OrderedDict()
        self._client_connected_cb = client_connected_cb
        self._client_disconnected_cb = client_disconnected_cb
        self.client_pid = -1
        self.state = ClientState.Unknown
        self.transport = None
        self.is_elevated = False
        self.executable_path = ""
        self.reader_task = None
        self.user_name = None
        if loop is None:
            self.loop = asyncio.get_event_loop()
        else:
            self.loop = loop

    async def get_message(self, id):
        while True:
            if id in self.responses:
                return self.responses[id]
            encoded = await self.response_queue.get()
            message = agent_encoder.agent_decode(encoded)
            log.debug("decoded message: '{}'".format(message))
            self.responses[message.id] = message

    def connection_made(self, transport):
        log.debug('new connection.')
        loop = self.loop
        self.transport = transport
        self.state = ClientState.Connected
        self.client_pid = win32pipe.GetNamedPipeClientProcessId(self.transport.get_extra_info('pipe').handle)
        self.is_elevated = caldera_utils.process_is_elevated(self.client_pid)
        self.executable_path = caldera_utils.process_path(self.client_pid)
        self.user_name = '\\'.join(caldera_utils.sid_user(caldera_utils.process_sid(self.client_pid)))
        loop.create_task(self.server_handshake())

    async def server_handshake(self):
        loop = self.loop
        try:
            handshake = agent_encoder.RatMessage(opcode=agent_encoder.RatOpcodes.Initiate)
            self.send_message(handshake)
            handshake_response = await self.get_message(handshake.id)
            if handshake_response.opcode == agent_encoder.RatOpcodes.Initiate:
                self.state = ClientState.Implant
                loop.call_soon(log.info, "Connected to implant {}".format(self.client_pid))
                if self._client_connected_cb is not None:
                    loop.create_task(self._client_connected_cb(self))
            else:
                loop.call_soon(log.warning, "Handshake with client {} failed.".format(self.client_pid))
                self.transport.close()
        except Exception as e:
            log.warning("Agent Protocol handshake with client {} failed:\n{}".format(self.client_pid, e))
            self.transport.close()

    def send_message(self, message: agent_encoder.RatMessage):
        log.debug("Sending message {}".format(message))
        self.transport.write(agent_encoder.agent_encode(message))

    def data_received(self, data):
        loop = self.loop
        if self.state not in (ClientState.Connected, ClientState.Implant):
            loop.call_soon(log.warning, "Received data while not in connected or implant state: {}".format(data))
            return
        self.buf.append(data)

        if b'\n' in data:
            lines = b''.join(self.buf)
            split = lines.split(b'\n')
            if split[-1] != b'':
                # the last split did not end with a newline
                self.buf = [split.pop(-1)]
            else:
                self.buf = []
                split.pop(-1)  # remove empty element b''
            for line in split:
                log.debug('adding line to self.responses queue: {}'.format(line))
                loop.create_task(self.response_queue.put(line))

    def connection_lost(self, exc):
        loop = self.loop
        # The socket has been closed
        loop.call_soon(log.info, "Disconnected from client {} with state {}".format(self.client_pid, self.state))

        self.state = ClientState.Gone

        if self.reader_task is not None:
            self.reader_task.cancel()

        if self._client_disconnected_cb is not None:
            res = self._client_disconnected_cb(self)
            if asyncio.iscoroutine(res):
                loop.create_task(res)

    async def run_function(self, function, params):
        message = agent_encoder.RatMessage(opcode=function, parameters=params)
        return await self.communicate(message)

    async def communicate(self, message):
        loop = self.loop
        loop.call_soon(self.send_message, message)

        self.reader_task = loop.create_task(self.get_message(message.id))

        try:
            message = await self.reader_task
            self.reader_task = None
        except asyncio.CancelledError:
            raise DisconnectedError()

        if message.response:
            return message.parameters
        else:
            raise Exception("Bad response")
