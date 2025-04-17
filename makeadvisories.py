#!/usr/bin/env python3

import madb.config as config
from madb.advisories import Advisories
import logging
import datetime
import humanize
import time
import os
import argparse

logger = logging.getLogger(__name__)
log_level = getattr(logging, config.LOG_LEVEL.upper())
logging.basicConfig(
    filename=os.path.join(config.LOG_PATH, "madb.log"),
    encoding="utf-8",
    level=log_level,
)


parser = argparse.ArgumentParser(description=help)
parser.add_argument(
    "-f",
    "--follow",
    help="do not exit and use internal timer between runs",
    action="store_true",
)
args = parser.parse_args()


def makecache():
    """
    Init the class Advisories to trigger the load, update and save of advisories list
    """
    start = datetime.datetime.now()
    adv = Advisories()
    elapsed = datetime.datetime.now() - start
    logging.info(
        f"Updating {config.APP_NAME} Advisories list took {humanize.naturaldelta(elapsed, minimum_unit='seconds')}"
    )


while True:
    makecache()
    print("Advisories list update done")
    if not args.follow:
        break
    time.sleep(config.MAKE_CACHE_FREQUENCY * 60)
