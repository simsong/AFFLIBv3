from distutils.core import setup, Extension

pyaff = Extension('pyaff',
                  libraries = ['afflib'],
                  sources = ['pyaff.c'])

setup (name = 'PyAFF',
       version = '0.1',
       description = 'Python wrapper for AFFLIB',
       author = 'David Collett',
       author_email = 'david.collett@gmail.com',
       url = 'www.pyflag.net',
       license = "GPL",
       ext_modules = [pyaff])
