# -*- coding: utf-8 -*-
"""
Create and draw an interactive representation of packages dependencies.

"""
#    Copyright (C) 2024 by Papoteur
#    Distributed with GPLv3 license.     
#    All rights reserved, see LICENSE for details.


__author__ = """Papoteur"""

from madb.dnf5madbbase import Dnf5MadbBase 
from networkx import Graph, get_node_attributes, set_node_attributes, spring_layout
import madb.config as config

from pyvis.network import Network

class RpmGraph():
    def __init__(self, release, arch, level, descending):
        self.base = Dnf5MadbBase(release, arch, config.DATA_PATH)
        self.level = level
        self.descending = bool(descending)

    def add_requires(self, ref, depth):
        '''
        Add all kind of dependencies
        '''
        deps = []
        process = [(ref.get_requires(),"blue"),
                   (ref.get_recommends(),"green"),
                   (ref.get_suggests(),"orange"),
                   (ref.get_supplements(), "braun")
                ]
        for l, link_color in process:
            previous = ""
            if l is None:
                print(f"{link_color} is void")
                continue
            i = 1
            p_name = ""
            for req in l:
                query = self.base.provides_requires(req)
                for p in list(query):
                    if not p.get_name() in deps:
                        deps.append(p.get_name())
                    # p is a libdnf5.rpm.Package object
                    i += 1
                    if (p.get_name() == p_name) :
                        continue
                    p_name = p.get_name()
                    if p_name in self.G.nodes() :
                    # il faut avoir le lien de dépendance, perdu par la relation provides_requires
                        attrs = get_node_attributes(self.G, 'title')
                        attrs[p_name] = f"{attrs[p_name]}<br>- {str(req)} (by {ref.get_name()})"
                        set_node_attributes(self.G,attrs,'title')
                    else:
                        self.G.add_node(p_name,
                                name=p_name,
                                title=f"<a href='/graph?rpm={p_name}'>{p_name}</a><br>Version: {p.get_evr()}<br>Required through:<br>- {str(req)} (by {ref.get_name()})",
                                version=p.get_evr(),
                                color= ' orange',
                            )
                    self.G.add_edge(ref.get_name(), p_name,
                                name=ref.get_name(),
                                version= ref.get_version(),
                                arrows="to",
                                title=str(req) ,
                                color=link_color)
                    if p_name != previous:
                        if depth <= self.level - 2:
                            self.add_requires(p, depth + 1)
                    previous = p_name

    def add_parents(self, ref, depth):
        '''
        Add all kind of parent dependencies
        '''
        deps = []
        process = [("requires","blue"),
                   ("recommends","green"),
                   ("suggests","orange"),
                   ("supplements", "braun")
                ]
        for link_type, link_color in process:
            previous = ""
            l = self.base.search_name([ref.get_name(),])
            for pkg in l:
                last = pkg
            if last is None:
                print(f"{link_color} is void")
                continue
            i = 1
            p_name = ""
            for p in self.base.search(link_type, last.get_provides()):
                    if not p.get_name() in deps:
                        deps.append(p.get_name())
                    # p is a libdnf5.rpm.Package object
                    i += 1
                    if (p.get_name() == p_name) :
                        continue
                    p_name = p.get_name()
                    if p_name not in self.G.nodes() :
                        self.G.add_node(p_name,
                                name=p_name,
                                title=f"<a href='/graph?rpm={p_name}'>{p_name}</a><br>Version: {p.get_evr()}",
                                color= ' orange',
                            )
                    self.G.add_edge(ref.get_name(), p_name,
                                name=ref.get_name(),
                                arrows="from",
                                color=link_color)
                    if p_name != previous:
                        if depth <= self.level - 2:
                            self.add_parents(p, depth + 1)
                    previous = p_name

    def graphe(self, name, descending=True):
        i = self.base.search_name([name])
        packages = list(i)
        for pkg in packages:
            self.G.add_node(pkg.get_name(), name=pkg.get_name(),
                                title=f"Version: {pkg.get_version()}",
                                color= ' red')
            if descending:
                self.add_requires(pkg, 0)
            else:
                self.add_parents(pkg, 0)
        if len(packages) == 0:
            print("Found nothing") 
        return (self.G.number_of_nodes(), self.G.number_of_edges())


    def render_vis(self, pkg):
        self.current_rpm = pkg
        self.G = Graph()
        nrn, nre = self.graphe(pkg, self.descending)
        if nrn == 0:
            return None
        newgraph =  Network('800px', width="100%", cdn_resources="local")
        # newgraph =  Network('800px', width="100%", cdn_resources="local", layout={"hierarchical": {"direction": "UD"}})
        newgraph.from_nx(self.G)
        newgraph.repulsion(damping=0.06)
        return newgraph
