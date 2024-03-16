#!/usr/bin/env python3

import madb.config as config
from madb.dnf5madbbase import Dnf5MadbBase
import logging

for distro in iter(config.DISTRIBUTION.keys()):
    for arch in iter(config.ARCHES.keys()):
        print(f"{distro} {arch}" )
        base = Dnf5MadbBase(distro, arch, config.DATA_PATH, refresh=True)
logging.info("Updated {config.APP_NAME} metadata")