# Copyright (C) 2013 THE MADB'S COPYRIGHT HOLDER
# This file is distributed under the same license as the madb package.

# This Makefile is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.


VERSION = 0.6.1

PACKAGE = madb
GITPATH = git@github.com:manatools/madb.git

all: version 

version:
	echo "RELEASE='$(VERSION)'" > madb/version.py


clean:
	madb*.tar.xz


install: version

# rules to build tarball

dist: tar
tar:
	git archive --prefix $(PACKAGE)-$(VERSION)/ $(VERSION) | xz -9 > $(PACKAGE)-$(VERSION).tar.xz
