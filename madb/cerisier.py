# -*- coding: utf-8 -*-
"""
Create and draw an interactive representation of packages dependencies.

"""
#    Copyright (C) 2020 by Papoteur
#    Distributed with GPLv3 license.     
#    All rights reserved, see LICENSE for details.


__author__ = """Papoteur"""

from madb.dnf5madbbase import Dnf5MadbBase 
from networkx import Graph, get_node_attributes, set_node_attributes, spring_layout
from bokeh.plotting import figure, from_networkx, curdoc
from bokeh.models import Rect, HoverTool, LabelSet, CustomJSTransform, TextInput, Slider, MultiLine, Div, Button
from bokeh.transform import transform
from bokeh.layouts import column, row
from bokeh.resources import CDN
import madb.config as config

class RpmGraph():
    def __init__(self, release, arch, level, descending):
        self.base = Dnf5MadbBase(release, arch, config.DATA_PATH)
        self.level = level
        self.descending = bool(descending)

    def run(self, current_rpm):
        self.current_rpm = current_rpm
        self.hist = []
        plot = self.render(self.current_rpm)
        self.field = TextInput(value=self.current_rpm, title="Select package: ")
        self.level_slider = Slider(start=1, end=5, step=1, value=self.level, title="Deepth")
        back_bt = Button(label="Back")
        self.field.on_change('value', self.update)
        self.level_slider.on_change('value', self.update_level)
        back_bt.on_click(self.back)

        # put the field, slider, button and plot in a layout and add to the document
        self.layout = column(row(self.field, self.level_slider, back_bt), plot)
        self.layout.sizing_mode ="scale_width"
        curdoc().add_root(self.layout)
        return plot

    def add_requires(self, ref, deepth):
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
                        attrs = get_node_attributes(self.G, 'req')
                        attrs[p_name] = f"{attrs[p_name]} {str(req)}/{ref.get_name()}"
                        set_node_attributes(self.G,attrs,'req')
                    else:
                        self.G.add_node(p_name,
                                name=p_name,
                                version=p.get_evr(),
                                width=(len(p_name) * 0.018 + 0.05 ),
                                offset= -len(p_name) * 2.5 - 6,
                                color= ' cornsilk',
                                req= f"{str(req)}/{ref.get_name()}",
                            )
                    self.G.add_edge(ref.get_name(), p_name,
                                name=ref.get_name(),
                                version= ref.get_version(),
                                req=str(req) ,
                                color=link_color)
                    if p_name != previous:
                        if deepth <= self.level - 2:
                            self.add_requires(p, deepth + 1)
                    previous = p_name



    def add_parents(self, ref, deepth):
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
            l = self.base.search(link_type, [ref.get_name(),])
            if l is None:
                print(f"{link_color} is void")
                continue
            i = 1
            p_name = ""
            for p in l:
                #query = self.base.provides_requires(req)
                #for p in list(query):
                    if not p.get_name() in deps:
                        deps.append(p.get_name())
                    # p is a libdnf5.rpm.Package object
                    i += 1
                    if (p.get_name() == p_name) :
                        continue
                    p_name = p.get_name()
                    if p_name in self.G.nodes() :
                    #    attrs = get_node_attributes(self.G, 'req')
                    #    attrs[p_name] = f"{attrs[p_name]} {str(req)}/{ref.get_name()}"
                    #    set_node_attributes(self.G,attrs,'req')
                        pass
                    else:
                        self.G.add_node(p_name,
                                name=p_name,
                                version=p.get_evr(),
                                width=(len(p_name) * 0.018 + 0.05 ),
                                offset= -len(p_name) * 2.5 - 6,
                                color= ' cornsilk',
                                #req= f"{str(req)}/{ref.get_name()}",
                                req = "",
                            )
                    self.G.add_edge(ref.get_name(), p_name,
                                name=ref.get_name(),
                                version= ref.get_version(),
                                #req=str(req) ,
                                req = "",
                                color=link_color)
                    if p_name != previous:
                        if deepth <= self.level - 2:
                            self.add_parents(p, deepth + 1)
                    previous = p_name

    def graphe(self, name, descending=True):
        i = self.base.search_name([name])
        packages = list(i)
        for pkg in packages:
            self.G.add_node(pkg.get_name(), name=pkg.get_name(),
                                version=pkg.get_version(),
                                width=(len(pkg.get_name()) * 0.018 + 0.05 ),
                                offset=- len(pkg.get_name()) * 2.5 - 6,
                                color= ' red',
                                req="")
            if descending:
                self.add_requires(pkg, 0)
                print("Descending")
            else:
                self.add_parents(pkg, 0)
                print("Ascending")
        if len(packages) == 0:
            print("Found nothing") 
        return (self.G.number_of_nodes(), self.G.number_of_edges())


    def update_level(self, attr, old, new):
        # triggerred when level slider is updated
        self.level = int(new)
        self.update(attr, self.current_rpm, self.current_rpm)

    def update(self, attr, old, new):
        # triggered when field value is changed or called when level is changed
        print(f"Selected {new}")
        newplot = self.render(new)
        self.layout.children[1] = newplot

    def render(self, pkg):
        self.current_rpm = pkg
        self.hist.append([pkg, self.level])
        self.G = Graph()
        nrn, nre = self.graphe(pkg, self.descending)
        if nrn == 0:
            return Div(text="This package is unknown")
        newgraph = from_networkx(self.G, spring_layout, scale=2, center=(0,0))
        newplot = figure( sizing_mode ="scale_width", aspect_ratio=2, x_range=(-2.2, 2.2), y_range=(-2.1, 2.1),
                tools="tap", toolbar_location=None)
        newplot.axis.visible = False
        newplot.grid.visible = False
        newgraph.node_renderer.glyph = Rect(height=0.07, width=0.1, fill_color="color", fill_alpha=0.0, line_alpha=0.0)
        if nre != 0:
            newgraph.edge_renderer.glyph = MultiLine(line_color="color", line_alpha=0.8)
        newplot.renderers.append(newgraph)
        self.source = newgraph.node_renderer.data_source
        xcoord = CustomJSTransform(v_func=self.code % "0", args=dict(provider=newgraph.layout_provider))
        ycoord = CustomJSTransform(v_func=self.code % "1", args=dict(provider=newgraph.layout_provider))
        self.source.selected.on_change('indices', self.selected)
        labels = LabelSet(x=transform('index', xcoord),
                    y=transform('index', ycoord),
                    text='name', text_font_size="12px",
                    y_offset=-6, x_offset= "offset" ,
                    background_fill_color='color', background_fill_alpha=0.85,
                    border_line_color='color', border_line_alpha=1.0,
                    source=self.source, render_mode='canvas')
        newplot.add_tools(self.hover)
        newplot.add_layout(labels)
        return newplot

    def selected(self, attr, old, new):
        # triggered when package tag is clicked
        pkg = self.source.data['name'][new[0]]
        self.field.value = pkg

    def back(event):
        # triggered when the back button is pressed
        if len(self.hist) > 1:
            # the last record in hist is the current display. We want the previous. This one will be added again when calling an update, thus we need to delete it from the list before.
            pkg, new_level = self.hist[-2]
            del self.hist[-1]
            del self.hist[-1]
            if new_level != self.level :
                self.level = new_level
                # trigger rendering
                self.level_slider.value = self.level
            if pkg != self.current_rpm :
                # trigger rendering
                self.field.value = pkg
    # Helper to get position of nodes and puttext label at adequate place
    code = """
        var result = new Float64Array(xs.length)
        for (var i = 0; i < xs.length; i++) {
            result[i] = provider.graph_layout[xs[i]][%s]
        }
        return result
    """
    # Add tooltips on each package tag
    hover = HoverTool()
    hover.tooltips = [
            ('name','@name'),
            ('version','@version'),
            ('link through/by','@req')
            ]

