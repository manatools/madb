#!/bin/bash
# Démarrer plusieurs processus
/usr/bin/makecache.py -f &
/usr/bin/gunicorn --workers=8 --timeout=90 wsgi:madb_app --log-level=INFO --bind=:5003 &
wait
