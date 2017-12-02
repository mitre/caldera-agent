python setup.py clean --all
del _foster3*.pyd
python setup.py build_ext --inplace
python setup.py py2exe