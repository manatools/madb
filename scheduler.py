from subprocess import run
import time
import logging
import madb.config as config
import os

logger = logging.getLogger(__name__)
log_level = getattr(logging, config.LOG_LEVEL.upper())
logging.basicConfig(filename=os.path.join(config.LOG_PATH,'anitya.log'),
                    encoding='utf-8',
                    level=log_level,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

while 1:
    p = run(['python', 'check_anitya_dnf.py', "-u", "-l", "INFO"], capture_output=True)
    if p.returncode != 0:
        logging.warning(p.stderr.decode('utf8'))
        print(p.stderr.decode('utf8'))
    # every 10 minutes
    time.sleep(600)
    
