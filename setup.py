#!/usr/bin/env python

import sys
from codecs import open

from setuptools import setup

CURRENT_PYTHON = sys.version_info[:2]
REQUIRED_PYTHON = (3, 8)

if CURRENT_PYTHON < REQUIRED_PYTHON:
    sys.stderr.write(
        """
==========================
Unsupported Python version
==========================
This version of Xython requires at least Python {}.{}, but
you're trying to install it on Python {}.{}. To resolve this,
consider upgrading to a supported Python version.

""".format(
            *(REQUIRED_PYTHON + CURRENT_PYTHON)
        )
    )
    sys.exit(1)


requires = [
    "celery>=2",
    "requests>=2",
    "pytz"
]
test_requirements = [
    "pytest>=3",
]

with open("README.md", "r", "utf-8") as f:
    readme = f.read()

setup(
    name="xython",
    version="0.1.1",
    description="xython is a rewrite in python of xymon",
    long_description=readme,
    long_description_content_type="text/markdown",
    author="Corentin Labbe",
    author_email="clabbe.montjoie@gmail.com",
    url="https://github.com/xython-monitoring/xython",
    packages=["xython", "xython_tlsd", "xython_ncurses"],
    package_data={"": ["LICENSE", "NOTICE"]},
    package_dir={"xython": "xython", "xython_tlsd": "xython-tlsd", "xython_ncurses": "xython-ncurses"},
    entry_points={
        'console_scripts': [
            "xythond = xython:main",
            "xython-tlsd = xython_tlsd.xython_tlsd:main",
            "xythonc = xython.xython_client:main",
            "xython-nshow = xython_ncurses.xython_nshow:main",
        ],
    },
    include_package_data=True,
    python_requires=">=3.7",
    install_requires=requires,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: System :: Monitoring",
    ],
    tests_require=test_requirements,
)
