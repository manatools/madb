#!/bin/bash
# processus de mise à jour du cache des métadonénes de DNF
/usr/bin/python3 /var/lib/madb/makecache.py -f &
# Démarrer plusieurs processus
/usr/bin/gunicorn --workers=8 --timeout=90 wsgi:madb_app --log-level=INFO --bind=:5003 &
# process for collecting anitya data: first pass then update process
/usr/bin/python3 /var/lib/madb/check_anitya_dnf.py -f -l INFO > /dev/null 2> anitya-error.log; /usr/bin/python3 /var/lib/madb/scheduler.py > /dev/null 2>> anitya-error.log &
wait
