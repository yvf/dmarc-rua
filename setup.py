from setuptools import setup, find_packages

setup(
    name = "dmarc-rua",
    version = "0.1",
    install_requires = [ 'Click', 'dnspython' ],
    py_modules = [ 'dmarc_rua_verify' ],
    entry_points='''
        [console_scripts]
        dmarc_rua_verify=dmarc_rua_verify:main
    '''
)
