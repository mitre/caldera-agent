from setuptools import setup, Extension
import sys
from pathlib import PureWindowsPath


sys.path.append(str(PureWindowsPath(sys.path[0]).parent))

try:
    # needs to be imported to compile .exes
    import py2exe
except ImportError:
    print("Could not find py2exe module, please install py2exe to site-packages")
    exit()

opts = {}
zipfile = 'library.zip'

if len(sys.argv) == 2 and sys.argv[1] == "py2exe":
    print("Building self-contained .exe")
    opts = {'py2exe': {'bundle_files': 1,
                       'compressed': True,
                       'unbuffered': True,
                       }
            }
    zipfile = None

class Target:
    def __init__(self, **kw):
        self.__dict__.update(kw)
        # for the versioninfo resources
        self.version = "0.1.0"
        self.company_name = "The MITRE Corporation"
        self.copyright = "2017 The MITRE Corporation"
        self.name = "cagent"

requires = [
    'pywin32>=220',
    'py2exe>=0.9.2.2',
    'pyyaml>=3.11',
    'python>=3.5.0'
    ]
    
cagent = Target(
    # used for the versioninfo resource
    description="The CALDERA Agent service",
    modules=["cagent"],
    cmdline_style='custom',
    )

foster_mod = Extension('_foster3', sources=['_foster3.c'], libraries=["advapi32"])

setup(
    ext_modules=[foster_mod],
    service=[cagent],
    options=opts,
    zipfile=zipfile
    )
