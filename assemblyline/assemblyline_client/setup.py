#!/usr/bin/env python
"""Assemblyline Client Library PiP Installer"""

from setuptools import setup

import assemblyline_client

setup(
    name='assemblyline_client',
    version='.'.join(map(str, assemblyline_client.__build__)),
    description='Assemblyline client library',
    long_description="The Assemblyline client library facilitates issuing requests to the Assemblyline framework.",
    license='MIT',
    url='https://bitbucket.org/cse-assemblyline/assemblyline_client',
    author='CSE-CST Assemblyline development team',
    author_email='assemblyline-cse-cst@googlegroups.com',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
    ],
    entry_points={
        'console_scripts': [
            'al-submit=assemblyline_client.submit:main',
        ],
    },
    install_requires=[
        'pycrypto',
        'requests',
        'requests[security]',
        'socketio-client==0.5.6'
    ],
    keywords='development assemblyline client gc canada cse-cst cse cst',
    packages=[
        'assemblyline_client'
    ],
)
