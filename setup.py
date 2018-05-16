"""setup.py file."""

from setuptools import setup, find_packages

__author__ = 'Gabriele Gerbino <gabriele@networktocode.com>'

with open("requirements.txt", "r") as fs:
    reqs = [r for r in fs.read().splitlines() if (len(r) > 0 and not r.startswith("#"))]

setup(
    name="napalm-panos",
    version="0.5.2",
    packages=find_packages(),
    author="Gabriele Gerbino",
    author_email="gabriele@networktocode.com",
    description="Network Automation and Programmability Abstraction Layer with Multivendor support",
    classifiers=[
        'Topic :: Utilities',
         'Programming Language :: Python',
         'Programming Language :: Python :: 2',
         'Programming Language :: Python :: 2.7',
        'Operating System :: POSIX :: Linux',
        'Operating System :: MacOS',
    ],
    url="https://github.com/napalm-automation/napalm-panos",
    include_package_data=True,
    install_requires=reqs,
)
