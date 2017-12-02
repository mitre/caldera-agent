"""
This module handles the creation of conf.yml which holds the configuration for the rats (agent_configurator).
"""
import os


def config_path():
    file_path = os.path.realpath(__file__)
    if file_path.endswith("pyc"):  # This is necessary because when running as service caldera_agent.pyc is appended
        # to this executable's path
        return os.path.join(os.path.dirname(os.path.dirname(file_path)), "conf.yml")
    else:
        return os.path.join(os.path.dirname(file_path), "conf.yml")
