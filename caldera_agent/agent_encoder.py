import base64
import json
import os
""" Simple functions used for preparing and processing data which traverses the
 pipe. Currently, dicts are jsonified and base64'd before traversing the pipe, however, this module can be extended
 for different data types or formats (BSON may become a desirable alternative to json at some point). The intention
 for placing these functions in their own module is to make it easier to troubleshoot communication errors that arise
 from encoding problems, and avoid mismatched encoding schemes as further development is done on the Agent and Implants
 """


class RatOpcodes(object):
    # these are the only opcodes that the agent should be aware of
    # any others will be passed through
    Initiate = "initiate"
    Exit = "exit"


class RatMessage(object):
    _max_id = os.getpid() * 100
    """
    :param RatMessage opcode: One of the valid opcodes
    :param bool response: True if sent from the rat
    :param int id: Identifier (unused)
    :param [String, String] parameters:
    """
    def __init__(self, opcode=None, response=False, id=None, parameters=None):
        self.opcode = opcode
        self.response = response
        self.id = RatMessage._max_id if id is None else id
        if id is None:
            RatMessage._max_id += 1
        self.parameters = {} if parameters is None else parameters

    def to_dict(self):
        return dict(opcode=self.opcode, response=self.response, id=self.id, parameters=self.parameters)

    def __str__(self):
        return '{}({})'.format(type(self).__name__, self.to_dict())

    __repr__ = __str__


def agent_encode(message: RatMessage) -> str:
    # dict -> json -> ascii -> (base64 + newline)
    result = base64.b64encode(json.dumps(message.to_dict(), sort_keys=True).encode('UTF-8')) + b'\n'
    return result


def agent_decode(incoming_bytes: str) -> RatMessage:
    # (base64 + newline) -> ascii -> json -> dict
    result = json.loads(base64.b64decode(incoming_bytes.strip()).decode('UTF-8'))
    return RatMessage(**result)
