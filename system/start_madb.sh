#!/bin/bash
# Démarrer plusieurs processus
makecache.py &
/usr/bin/gunicorn --workers=8 --timeout=90 wsgi:madb_app --log-level=INFO --bind=:5003 &
wait
