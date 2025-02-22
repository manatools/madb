#!/usr/bin/env python3

import madb.config as config
from madb.dnf5madbbase import Dnf5MadbBase
import logging
import datetime
import humanize
import time
import os

logger = logging.getLogger(__name__)
log_level = getattr(logging, config.LOG_LEVEL.upper())
logging.basicConfig(filename=os.path.join(config.LOG_PATH,'madb.log'), encoding='utf-8', level=log_level)

def makecache():
    start = datetime.datetime.now()
    for distro in iter(config.DISTRIBUTION.keys()):
        if distro != "unspecified":
            for arch in iter(config.ARCHES.keys()):
                if arch != "indifferent":
                    try:
                        base = Dnf5MadbBase(distro, arch, config.DATA_PATH, refresh=True)
                    except Exception as e:
                        logging.info(f"Updating {config.APP_NAME} metadata for {distro} {arch} failed with:\n{e.with_traceback()}")
        elapsed =  datetime.datetime.now() - start
        logging.info(f"Updating {config.APP_NAME} metadata took {humanize.naturaldelta(elapsed, minimum_unit='seconds')}")

while True:
    makecache()
    time.sleep(config.MAKE_CACHE_FREQUENCY * 60)