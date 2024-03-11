#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import itertools

import statistics

impls: list[str] = ["jasmin", "ref"]
options:list[str] = ["f", "s"]
sizes:list[int] = [128, 192, 256]
thashes:list[str] = ['robust', 'simple']

MIN_MSG_LEN = 1
MAX_MSG_LEN = 128
AVG_MSG_LEN = 64


# TODO: