#!/usr/bin/env python3

"""
This fetches a selection of update message ids from datagrepper to use for
checking Mageia packages versions.
"""
import requests
import sys
import json
import time
import os
from madb.dnf5madbbase import Dnf5MadbBase
import madb.config as config

from sqlalchemy import Column, Integer, String, DateTime, create_engine, update, select, delete
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime


distro = Dnf5MadbBase("cauldron", "x86_64", config.DATA_PATH)

Base = declarative_base()

# Définir la table Package
class Package(Base):
    __tablename__ = 'packages'
    id = Column(Integer, primary_key=True)
    name = Column(String(80), unique=True)
    our_version = Column(String(20))
    upstream_version = Column(String(20))
    updated_on = Column(DateTime)
    msg_id = Column(String(40))
    pkg_id = Column(Integer)
    maintainer = Column(String(40))

database_path = os.path.join(config.EXTERNAL_PATH, 'packages.db')
engine = create_engine('sqlite:///' + database_path, echo=True)

# Création de la table si elle n'existe pas
Base.metadata.create_all(engine)

# Session pour insérer ou interagir avec la base
Session = sessionmaker(bind=engine)

# Fonction d'ajout d'un package
def add_package(session, name, our_version, upstream_version, updated_on, msg_id, pkg_id, maintainer):
    package = Package(name=name,
                      our_version=our_version, 
                      upstream_version=upstream_version, 
                      updated_on=updated_on, 
                      msg_id=msg_id,
                      pkg_id=pkg_id,
                      maintainer=maintainer)
    session.add(package)

# Fonction de retrait d'un package
def remove_package(session, id):
    package = session.get(Package, id)
    session.delete(package)

# Fonction de mise à jour d'un package
def update_package(session, id, our_version, upstream_version, updated_on, msg_id, pkg_id, maintainer):
    package = session.get(Package, id)
    if our_version != "":
        package.our_version = our_version
    if upstream_version != "":
        package.upstream_version = upstream_version
    package.updated_on = datetime.fromtimestamp(updated_on)
    package.msg_id = msg_id
    package.pkg_id = pkg_id
    if maintainer != "":
        package.maintainer = maintainer

def cleaning(session, packages_list):
    stmt = delete(Package).where(Package.name.notin_(packages_list))
    session.execute(stmt)
    
def update_content(with_remote=False):
    """
    Start with a void database
    """
    packages = get_srpms()
    maintdb = get_maintdb()

    # add each package to the database and get upstream version
    with Session() as session:
        for package in packages:
            print(package.get_name())
            upstream_version = ""
            updated_on = 0
            pkg_id = 0
            present = False
            added = False
            # check if record exists
            name_to_find = package.get_name()
            stmt = select(Package).where(Package.name == name_to_find)
            result = session.execute(stmt).scalar_one_or_none()
            if result:
                present = True
                if  package.get_version() != result.our_version:
                    # update the version
                    print("Updating")
                    stmt = update(Package).\
                        where(Package.id == result.id).\
                        values(our_version=package.get_version(), maintainer=maintdb[package.get_name()])
                    session.execute(stmt)
                    print("Updated")
            if with_remote or not present:
                # get upstream info
                print("Remote")
                anityainfo = anitya_response(package)
                if ((anityainfo[3] != 'none') and (anityainfo[2] != 'None')):
                    upstream_version = anityainfo[2]
                    pkg_id = anityainfo[3]
                    updated_on = datetime.fromtimestamp(anityainfo[4])
                    # insert in database or update
                    if present:
                        print("Remote: updating")
                        stmt = update(Package).\
                                where(Package.id == result.id).\
                                values(upstream_version=upstream_version, pkg_id=pkg_id, updated_on=updated_on)
                        session.execute(stmt)
                        session.commit()
                        print("Remote: updated")
                    else: 
                        print("Remote: adding")
                        add_package(session, package.get_name(), package.get_version(), upstream_version, updated_on, "", pkg_id, maintdb[package.get_name()])
                        print("Remote: added")
                        added = True
            if not present and not added:
                print("Adding")
                add_package(session, package.get_name(), package.get_version(), "", None, "", 0, maintdb[package.get_name()])
                print("Added")

        # delete srpms no more listed
        cleaning(session, [pkg.get_name() for pkg in packages])
        session.commit()

    
UPDATE_URL = (
    "https://apps.fedoraproject.org/datagrepper/raw?topic=org."
    "release-monitoring.prod.anitya.project.version.update&"
    "delta=604800&rows_per_page=75"
)

def get_maintdb():
    maintdb_url = 'http://pkgsubmit.mageia.org/data/maintdb.txt'
    response = requests.get(maintdb_url)
    r = response.text
    maintdb = dict()
    for line in str(r).splitlines():
        try:
            maintdb[line.split()[0]] = line.split()[1]
        except IndexError:
            maintdb[line.split()[0]] = 'nobody'
    return(maintdb)

def get_srpms(reload = True):
    global distro
    pkgs_list = distro.search_nevra(["*"], repo="*SRPMS*")
    return pkgs_list

def anitya_response(package):
    anitya_id = 'none'
    anitya_version = 'none'
    anitya_url = 'https://release-monitoring.org'
    name = package.get_name()
    updated_on = ""

    url = '%s/api/project/Mageia/%s' % (anitya_url, name)
    try:
        response = requests.get(url)
        data = response.json()
    except:
        data = 'error'

    if not 'error' in data:
        anitya_id = data['id']
        anitya_version = data['version']
        updated_on = data['updated_on']
    else:
        url = '%s/api/project/Fedora/%s' % (anitya_url, name)
        try:
            response = requests.get(url)
            data = response.json()
        except:
            data = 'error'

        if not 'error' in data:
            anitya_id = data['id']
            anitya_version = data['version']
            updated_on = data['updated_on']

    return (name ,package.get_version(), anitya_version, anitya_id, updated_on)

def check_messages():
    response = requests.get(UPDATE_URL, timeout=30)
    updates = response.json()

    for message in updates["raw_messages"]:
        session = Session()
        name_to_find = message["msg"]["project"]["name"]
        stmt = select(Package).where(Package.name == name_to_find)
        result = session.execute(stmt).scalar_one_or_none()
        if result and message["msg_id"] != result.msg_id:
            update_package( 
                name_to_find,
                "",
                message["msg"]["project"]["version"],
                datetime.fromtimestamp( message["msg"]["project"]["updated_on"]),
                message["msg_id"],
                message["msg"]["project"]["id"],
                ""
                )

if __name__ == '__main__':
    update_content(with_remote=True)
    while True:
        time.sleep(3600)
        # Read monitor messages and update
        check_messages()
        # Read metadata and update
        update_content()
        

