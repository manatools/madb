# madb
Site for displaying RPM packages

Use `libdnf5` as provider for packages database 
Use `bugs.mageia.org` for special pages

# Requirements
The application needs this:
## Python modules
beautifulsoup4
flask
gunicorn
humanize
libdnf5 [1]
pandas
pyvis [2]
jsonpickle [2]

## Other packages
rpmlint-mageia-policy 

[1] For Mageia 9, this module is available from Copr: ngompa/dnf5-mga. For cauldron, it is already available in release.
[2] these packages are availble on MLO repository.

# Running
For testing purposes, the application can be run from the madb subdirectory, in debug mode to allow the application being reloaded when files are changed:
`flask run -d`
In production mode, it can be run with `gunicorn` from the root of the directory (the one containg `wsgi.py`):
`/usr/bin/gunicorn --workers 4 --timeout=90  wsgi:madb_app --log-level=INFO --bind :5003`
The application listens on port 5003 in this case.
Metadata from DNF are stored in `dnf/cache/`
Some files are cached in `cache/` or `cache/long/`. They are header files for the navigation bar and screenshots read from Debian repository.
The application writes logs in `./madb.log`.
The tool `python makecache.py` can be run regularly to allow the application to be more responsive.

# Testing
in the root directory, run:
`python -m pytest`
