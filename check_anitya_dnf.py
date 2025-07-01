#!/usr/bin/env python3

"""
This fetches a selection of update message ids from datagrepper to use for
checking Mageia packages versions.
"""
import requests
import sys
import json
import time
from madb.dnf5madbbase import Dnf5MadbBase
import madb.config as config

from sqlalchemy import Column, Integer, String, DateTime, create_engine, update, select, delete
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import time


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

engine = create_engine('sqlite:///madb/static/packages.db', echo=True)

# Création de la table si elle n'existe pas
Base.metadata.create_all(engine)

# Session pour insérer ou interagir avec la base
Session = sessionmaker(bind=engine)

# Fonction d'ajout d'un package
def add_package(name, our_version, upstream_version, updated_on, msg_id, pkg_id, maintainer):
    session = Session()
    package = Package(name=name,
                      our_version=our_version, 
                      upstream_version=upstream_version, 
                      updated_on=updated_on, 
                      msg_id=msg_id,
                      pkg_id=pkg_id,
                      maintainer=maintainer)
    session.add(package)
    session.commit()

# Fonction de retrait d'un package
def remove_package(id):
    session = Session()
    package = session.get(Package, id)
    session.delete(package)
    session.commit()

# Fonction de mise à jour d'un package
def update_package(id, our_version, upstream_version, updated_on, msg_id, pkg_id, maintainer):
    session = Session()
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
    session.commit()

def cleaning(packages_list):
    session = Session()
    stmt = delete(Package).where(Package.name.notin_(packages_list))
    session.execute(stmt)
    
def update_content(with_remote=False):
    """
    Start with a void database
    """
    packages = get_srpms()
    maintdb = get_maintdb()
    # add each package to the database and get upstream version
    session = Session()

    for package in packages:
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
                stmt = update(Package).\
                    where(Package.id == result.id).\
                    values(our_version=package.get_version(), maintainer=maintdb[package.get_name()])
                session.execute(stmt)
        if with_remote:
            # get upstream info
            anityainfo = anitya_response(package)
            if ((anityainfo[3] != 'none') and (anityainfo[2] != 'None')):
                upstream_version = anityainfo[2]
                pkg_id = anityainfo[3]
                updated_on = datetime.fromtimestamp(anityainfo[4])
                # insert in database or update
                if present:
                    stmt = update(Package).\
                            where(Package.id == result.id).\
                            values(upstream_version=upstream_version, pkg_id=pkg_id, updated_on=updated_on)
                else: 
                    add_package(package.get_name(), package.get_version(), upstream_version, updated_on, "", pkg_id, maintdb[package.get_name()])
                    added = True
        if not present and not added:
                add_package(package.get_name(), package.get_version(), "", None, "", 0, maintdb[package.get_name()])

    # delete srpms no more listed
    cleaning([pkg.get_name() for pkg in packages])

    
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
        session = Session()
        stmt = select(Package).where(Package.upstream_version != "").\
            where(Package.our_version != Package.upstream_version)
        # stmt = select(Package).where(Package.upstream_version == "") 
        packages = session.execute(stmt).scalars().all()
        f = open('madb/static/check_anitya.html','w')
        if 1:
            print('<!DOCTYPE html><html lang="en"><head><title>Check release-monitoring.org for Mageia packages</title></head>',  sep=' ', end='\n', file=f)
            print('<body><h1>Check release-monitoring.org for Mageia packages</h1>',  sep=' ', end='\n', file=f)
            print('<h3>',time.strftime("%Y-%m-%d %H:%M"), ' (', datetime.now().astimezone().tzinfo, ')</h3>', sep='', end='\n', file=f)
            print('<table id="anitya"><tr><thead>','<th>Name</th>', '<th>Mageia</th>', '<th>Anitya</th>', '<th>Maintainer</th>', '<th>release-monitoring.org id</th>', '</tr></thead>',  sep=' ', end='\n', file=f)
            print('<tbody>',  sep=' ', end='\n', file=f)
            f.flush()
            for package in packages:
                print(package.id, package.our_version)
                print('<tr>', '<td>'+package.name+'</td>', 
                '<td>'+package.our_version+'</td>',
                '<td>'+package.upstream_version+'</td>',
                '<td>'+str(maintdb[package.name])+'</td>',
                '<td><a href="https://release-monitoring.org/project/'+str(package.pkg_id)+'">'+str(package.pkg_id)+'</a></td>',
                '</tr>', sep=' ', end='\n', file=f)
            f.flush()
        print('</tbody></table>', sep=' ', end='\n', file=f)
        print('<script src="tablefilter/tablefilter.js"></script>',  sep=' ', end='\n', file=f)
        print('<script data-config>',  sep=' ', end='\n', file=f)
        print("var filtersConfig = {base_path: 'tablefilter/',alternate_rows: true, col_1: 'none', col_2: 'none', col_4: 'none', popup_filters: true, };",  sep=" ", end="\n", file=f)
        print("var tf = new TableFilter('anitya', filtersConfig);",  sep=" ", end="\n", file=f)
        print('tf.init();', '</script>',  sep=' ', end='\n', file=f)
        print('</body>', '</html>',  sep=' ', end='\n', file=f)
        f.close()
        time.sleep(3600)
        # Read monitor messages and update
        check_messages()
        # Read metadata and update
        update_content(with_remote=True)
        

