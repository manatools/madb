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

<<<<<<< HEAD
=======
# Configuration
The package comes with a model of configuration file `madb/config.py.in`. This file has to be edited and installed as `madb/config.py`. Its content is:
```
# the last release
TOP_RELEASE = 9
APP_NAME = "Mageia App DB"
DATA_PATH = "/var/www/html/madb"
MIRROR_URL = "https://fr2.rpmfind.net/linux/mageia/distrib/"
# Complete list of used goups
DEF_GROUPS_FILE = "/usr/share/rpmlint/config.d/distribution.exceptions.conf"
# Name of the development version
DEV_NAME = "cauldron"
# Level of logging
LOG_LEVEL = "DEBUG"
PAGE_SIZE = 30
BUGZILLA_URL = "http://bugs.mageia.org"
# List of architectures managed
ARCHES = {
    "x86_64": "x86 64bits",
    "i586": "x86 32bits",
    "aarch64": "Arm 64bits",
    "armv7hl": "Arm 32bits v7hl",
}
# Used as filter in search bar
DISTRIBUTION = {
    DEV_NAME: "Mageia cauldron",
    str(TOP_RELEASE): "Mageia " + str(TOP_RELEASE),
    str(TOP_RELEASE - 1): "Mageia " + str(TOP_RELEASE -1),
}
```

`TOP_RELEASE` has to be changed at each release.

`DATA_PATH` has to be adapted to where the application is located.

`MIRROR_URL` has to be adapted to be preferably a mirror near the server.

# Running
For testing purposes, the application can be run from the madb subdirectory, in debug mode to allow the application being reloaded when files are changed:

`flask run -d`

In production mode, it can be run with `gunicorn` from the root of the directory (the one containg `wsgi.py`):

`/usr/bin/gunicorn --workers 4 --timeout=90  wsgi:madb_app --log-level=INFO --bind :5003`

The application listens on port 5003 in this case.

Metadata from DNF are stored in `dnf/cache/`. The library writes also logs in `dnf/logs/`.

Some files are cached in `cache/` or `cache/long/`. They are header files for the navigation bar and screenshots read from Debian repository.

The application writes logs in `./madb.log`.

The tool `python makecache.py` can be run regularly to allow the application to be more responsive.

# Services
The application can be run as services through `systemd`. 

The file `system/gunicorn.socket` has to be installed in `/usr/lib/systemd/system`. It triggers the launch of `gunicorn.service` when the socket `/run/gurnicorn.sock` is accessed.

The file `system/gunicorn.service` has to be installed in `/usr/lib/systemd/system`. It provides the service of the application.

The file `system/madb-cache.service` has to be installed in `/usr/lib/systemd/system`. It provides the service of updating the dnf metadata on a regular basis.

The file `system/madb-cache.timer` has to be installed in `/usr/lib/systemd/system`.

# Testing
in the root directory, run:

`python -m pytest`
