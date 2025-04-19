#!/usr/bin/env python3

import madb.config as config
from madb.dnf5madbbase import Dnf5MadbBase
import logging
import datetime
import humanize
import time
import os
import traceback
import argparse

logger = logging.getLogger(__name__)
log_level = getattr(logging, config.LOG_LEVEL.upper())
logging.basicConfig(filename=os.path.join(config.LOG_PATH,'madb.log'), encoding='utf-8', level=log_level)


parser = argparse.ArgumentParser(description = help)
parser.add_argument("-f","--follow", help="do not exit and use internal timerbetween runs", action="store_true")
args = parser.parse_args()

def makecache():
    start = datetime.datetime.now()
    for distro in iter(config.DISTRIBUTION.keys()):
        if distro != "unspecified":
            for arch in iter(config.ARCHES.keys()):
                if arch != "indifferent":
                    try:
                        base = Dnf5MadbBase(distro, arch, config.DATA_PATH, refresh=True)
                        message = f"Repository {distro} {arch} up to date"
                        logging.debug(message)
                        print(message)
                    except Exception as e:
                        logging.warning(f"Updating {config.APP_NAME} metadata for {distro} {arch} failed with:\n{traceback.format_exc()}")
    elapsed =  datetime.datetime.now() - start
    message = f"Updating {config.APP_NAME} metadata took {humanize.naturaldelta(elapsed, minimum_unit='seconds')} at { datetime.datetime.now()}"
    logging.info(message)
    print(message)

while True:
    makecache()
    if not args.follow:
        break
    time.sleep(config.MAKE_CACHE_FREQUENCY * 60)
