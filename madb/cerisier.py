#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Create and draw an interactive representation of packages dependencies.

"""
#    Copyright (C) 2020 by Papoteur
#    Distributed with GPLv3 license.     
#    All rights reserved, see LICENSE for details.


__author__ = """Papoteur"""

import dnf

from networkx import Graph, get_node_attributes, set_node_attributes, spring_layout

from bokeh.plotting import figure, from_networkx, curdoc
from bokeh.models import Rect, HoverTool, LabelSet, CustomJSTransform, TextInput, Slider, MultiLine, Div, Button
from bokeh.transform import transform
from bokeh.layouts import column, row
global field
global source
global level
global current_rpm
global sack
global hist

base = dnf.Base()
conf = base.conf
conf.cachedir = '/tmp/my_cache_dir'
# this seems to take time at first launch. Needed to have list of non installed packages
base.read_all_repos()
sack = base.fill_sack(load_system_repo=False)
level = 2
hist = []
current_rpm = "workrave"
field = TextInput(value=current_rpm, title="Select package: ")
level_slider = Slider(start=1, end=5, step=1, value=level, title="Deepth")
back_bt = Button(label="Back")


def add_requires(ref, deepth, G):
    '''
    Add all kind of dependencies
    '''
    global level
    global sack
    process = [(ref.requires,"blue"),(ref.recommends,"green"),(ref.suggests,"orange"),(ref.supplements, "braun")]
    for query, link_color in process:
        previous = ""
        i = 1
        for req in list(query):
            # req is a _hawkey.Reldep object
            i += 1
            f = sack.query().filter(provides=req).latest()
            p_name = ""
            r = 1
            for p in list(f):
                r += 1
                if (p.name == p_name) :
                    continue
                p_name = p.name
                if p.name in G.nodes() :
                    attrs = get_node_attributes(G, 'req')
                    attrs[p.name] = f"{attrs[p.name]} {str(req)}/{ref.name}"
                    set_node_attributes(G,attrs,'req')
                else:
                    G.add_node(p.name,
                           name=p.name,
                            version=p.evr,
                            width=(len(p.name) * 0.018 + 0.05 ),
                            offset= -len(p.name) * 2.5 - 6,
                            color= ' cornsilk',
                            req= f"{str(req)}/{ref.name}" )
                G.add_edge(ref.name,p.name,
                           name=ref.name,
                            version= ref.version,
                            req=str(req) ,
                            color=link_color)
                if p.name != previous:
                    if deepth <= level - 2:
                        add_requires(p, deepth + 1, G)
                previous = p.name

def graphe(name, G):
    global sack
    i = sack.query().filter(name=name)
    packages = list(i)
    for pkg in packages:
        G.add_node(pkg.name, name=pkg.name,
                            version=pkg.version,
                            width=(len(pkg.name) * 0.018 + 0.05 ),
                            offset=- len(pkg.name) * 2.5 - 6,
                            color= ' red',
                            req="")
        add_requires(pkg, 0, G)
    if len(packages) == 0:
       print("Found nothing") 
    return (G.number_of_nodes(), G.number_of_edges())


def update_level(attr, old, new):
    # triggerred when level slider is updated
    global level
    global current_rpm
    level = int(new)
    update(attr, current_rpm, current_rpm)

def update(attr, old, new):
    # triggered when field value is changed or called when level is changed
    print(f"Selected {new}")
    newplot = render(new)
    layout.children[1] = newplot

def render(pkg):
    global current_rpm, level, hover, source
    current_rpm = pkg
    hist.append([pkg,level])
    newG = Graph()
    nrn, nre = graphe(pkg, newG)
    if nrn == 0:
        return Div(text="This package is unknown")
    newgraph = from_networkx(newG, spring_layout, scale=2, center=(0,0))
    newplot = figure(title="RPM network", sizing_mode ="scale_width", aspect_ratio=2, x_range=(-2.2, 2.2), y_range=(-2.1, 2.1),
              tools="tap", toolbar_location=None)
    newplot.axis.visible = False
    newplot.grid.visible = False
    newgraph.node_renderer.glyph = Rect(height=0.07, width=0.1, fill_color="color", fill_alpha=0.0, line_alpha=0.0)
    if nre != 0:
        newgraph.edge_renderer.glyph = MultiLine(line_color="color", line_alpha=0.8)
    newplot.renderers.append(newgraph)
    source = newgraph.node_renderer.data_source
    xcoord = CustomJSTransform(v_func=code % "0", args=dict(provider=newgraph.layout_provider))
    ycoord = CustomJSTransform(v_func=code % "1", args=dict(provider=newgraph.layout_provider))
    source.selected.on_change('indices', selected)
    labels = LabelSet(x=transform('index', xcoord),
                  y=transform('index', ycoord),
                  text='name', text_font_size="12px",
                  y_offset=-6, x_offset= "offset" ,
                  background_fill_color='color', background_fill_alpha=0.85,
                  border_line_color='color', border_line_alpha=1.0,
                  source=source, render_mode='canvas')
    newplot.add_tools(hover)
    newplot.add_layout(labels)
    return newplot

def selected(attr, old, new):
    # triggered when package tag is clicked
    global source
    pkg = source.data['name'][new[0]]
    field.value = pkg

def back(event):
    # triggered when the back button is pressed
    global hist
    global level
    if len(hist) > 1:
        # the last record in hist is the current display. We want the previous. This one will be added again when calling an update, thus we need to delete it from the list before.
        pkg, new_level = hist[-2]
        del hist[-1]
        del hist[-1]
        if new_level != level :
            level = new_level
            # trigger rendering
            level_slider.value=level
        if pkg != current_rpm :
            # trigger rendering
            field.value = pkg
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

plot = render(current_rpm)
field.on_change('value', update)
level_slider.on_change('value', update_level)
back_bt.on_click(back)

# put the field, slider, button and plot in a layout and add to the document
layout = column(row(field, level_slider,back_bt), plot)
layout.sizing_mode ="scale_width"
curdoc().add_root(layout)
