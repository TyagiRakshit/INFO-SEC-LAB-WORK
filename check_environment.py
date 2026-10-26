"""Run offline: python check_environment.py"""
import sys,importlib.util
print('Python:',sys.version.split()[0])
for name,package in [('Crypto','pycryptodome'),('phe','phe'),('cryptography','cryptography')]:
    print(f'{package}:', 'INSTALLED' if importlib.util.find_spec(name) else 'MISSING')
print('Run: python -m unittest discover -s tests -v')
