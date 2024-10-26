#!/usr/bin/env python3

import madb.config as config
from madb.dnf5madbbase import Dnf5MadbBase
import logging
import datetime
import humanize

start = datetime.datetime.now()

for distro in iter(config.DISTRIBUTION.keys()):
    for arch in iter(config.ARCHES.keys()):
        base = Dnf5MadbBase(distro, arch, config.DATA_PATH, refresh=True)
elapsed =  datetime.datetime.now() - start
print(f"Updating {config.APP_NAME} metadata took {humanize.naturaldelta(elapsed, minimum_unit='seconds')}")
