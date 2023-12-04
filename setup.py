#!/usr/bin/env python

from setuptools import setup

setup(
    name="querierd",
    version=0.6.2,
    description="IGMP querier service",
    author="David White",
    author_email="dr.white.nz@gmail.com",
    packages=["querier"],
    install_requires=["netifaces>=0.11.0"],
)
