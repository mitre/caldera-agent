# CALDERA Agent

The `caldera_agent` folder contains the source code of the CALDERA agent or 
*cagent* a Windows service that facilitates communication between
the CALDERA server and the CALDERA Rats. The cagent program should be installed 
on every computer that is taking part in the adversary emulation operation.
Once configured, they will connect to the CALDERA server
and be added as an option to take part in an operation. 

### Installation Requirements
The following are required on computers that the CALDERA Agent will be installed on

 - Windows 64 bit
 - [Visual C++ Redistributable](https://www.microsoft.com/en-us/download/details.aspx?id=48145)

Pre-compiled versions of cagent are available from the [Releases page](https://github.com/mitre/caldera-agent/releases). Installation steps may be found in [CALDERA's documentation](http://caldera.readthedocs.io/en/latest/installation.html#caldera-agent-installation).

### Build Requirements
Note: Pre-compiled versions of cagent are available from the [Releases page](https://github.com/mitre/caldera-agent/releases).

The following are required to build the CALDERA Agent

 - Windows 64 bit
 - Python 3.5 (64 bit)
 - python dependencies (`pip install -r requirements.txt`)
 - setuptools (`pip install --upgrade setuptools`) 
 - [PyWin32 v.220](https://sourceforge.net/projects/pywin32/files/pywin32/Build%20220/) or later.
 - Windows Visual Studio 2015 (with Visual C++) OR [Visual C++ 2015 Build Tools](http://landinghub.visualstudio.com/visual-cpp-build-tools)
 - [This version of py2exe](https://github.com/mitre/caldera-py2exe) (which is modified to work with Python 3.5)

### Building an .exe

After installing all the dependencies, go to the `caldera_agent` directory and build with
```
make.bat
```
The compiled executable will be located at `dist/cagent.exe`
