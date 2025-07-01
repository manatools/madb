#!/bin/bash
# processus de mise à jour du cache des métadonénes de DNF
/usr/bin/python3 /var/lib/madb/makecache.py -f &
# Démarrer plusieurs processus
/usr/bin/gunicorn --workers=8 --timeout=90 wsgi:madb_app --log-level=INFO --bind=:5003 &
# process for collecting anitya data
/usr/bin/python3 /var/lib/madb/check_anitya_dnf.py &
wait
