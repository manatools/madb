#!/usr/bin/env python3
from madb.helper import groups
from madb.helper import BugReport, Pagination, BugsList
from madb.helper import load_content_or_cache, clean_cache
from madb.cerisier import RpmGraph
from madb.screenshots import Screenshots
from flask import Flask, render_template, request, Response, send_from_directory, redirect
import requests
from bs4 import BeautifulSoup 
from csv import DictReader
from datetime import datetime, timedelta, date
import re
from io import StringIO
import collections
import madb.config as config
from urllib import parse
from madb.dnf5madbbase import Dnf5MadbBase
import humanize
import logging
import os
import threading
from packaging import version as pvers
import pandas as pd

logger = logging.getLogger(__name__)
log_level = getattr(logging, config.LOG_LEVEL.upper())
logging.basicConfig(filename=os.path.join(config.LOG_PATH,'madb.log'), encoding='utf-8', level=log_level)

URL = config.BUGZILLA_URL + "/buglist.cgi"

# start thread for cleaning cache
clean_thread = threading.Thread(target=clean_cache)
# clean_thread.start()

def create_app():
    app = Flask(__name__)
    app.config.from_object("madb.config")
    data_config = {}
    data_config["Next"] = config.TOP_RELEASE + 1
    data_config["App name"] = config.APP_NAME
    data_config["arches"] = config.ARCHES
    data_config["distribution"] = config.DISTRIBUTION

    # filter dor usage in templates
    @app.template_filter('bugs_sum')
    def bugs_sum(list_to_sum):
        return collections.Counter.total(list_to_sum)

    @app.route('/lib/<path:path>')
    def send_report(path):
        """ For serving files used by pyvis
        """
        return send_from_directory('lib', path)

    def navbar(lang=None):
        nav_html = load_content_or_cache("https://nav.mageia.org/html/?b=madb_mageia_org&w=1" + (f"&l={lang}" if lang is not None else ""))
        nav_css = load_content_or_cache("http://nav.mageia.org/css/")
        data = {"html": nav_html, "css": nav_css}
        return data

    @app.route("/")
    @app.route("/home")
    def home():        
        release = request.args.get("distribution", None)
        arch = request.args.get("architecture", None)
        graphical = request.args.get("graphical", "1")
        rpm = request.args.get("rpm", "")
        if not release:
            release = next(iter(config.DISTRIBUTION.keys()))
            arch = next(iter(config.ARCHES.keys()))
        distro = Dnf5MadbBase(release, arch, config.DATA_PATH)
        last_updates = distro.search_updates(last=True, testing=False)
        if not last_updates:
            last_updates = {}
        last_backports = distro.search_updates(backports=True, last=True, testing=False)
        if not last_backports:
            last_backports = {}
        groups1 = sorted(set([x[0] for x in groups()]))
        nav_data = navbar(lang=request.accept_languages.best)
        links = {}
        links["updates"] = "/list?type=updates"
        links["backports"] = "/list?type=backports"
        data = {
            "groups": groups1,
            "config": data_config,
            "title": "Home",
            "updates": last_updates,
            "backports": last_backports,
            "links": links,
            "rpm_search": rpm,
            "url_end": f"?distribution={release}&architecture={arch}&graphical=0",
            "base_url": "/home",
            "nav_html": nav_data["html"],
            "nav_css": nav_data["css"],
        }
        return render_template("home.html", data=data)

    @app.route("/list")
    def rpmlist():
        release = request.args.get("distribution", None)
        page = request.args.get("page", 1, type = int)
        arch = request.args.get("architecture", None)
        graphical = request.args.get("graphical", "0")
        rpm = request.args.get("rpm", "")
        type_list = request.args.get("type", "updates")
        testing = "testing" in type_list
        backports = "backports" in type_list
        if backports:
            title = "Backports"
        else:
            title = "Updates"
        if testing:
            title += " candidates"
        if not release:
            release = str(config.TOP_RELEASE)
            arch = next(iter(config.ARCHES.keys()))
        distro = Dnf5MadbBase(release, arch, config.DATA_PATH)
        rpms = distro.search_updates(backports=backports, testing=testing, graphical=(graphical == "1"))
        rpms = sorted(rpms, key=lambda rpm: rpm.get_build_time(), reverse=True)

        pager = Pagination(list(rpms), byweek=True)
        nav_data = navbar(lang=request.accept_languages.best)
        data = {
            "title": title,
            "rpms": pager.data_page(page),
            "links": pager.links(f"/list?distribution={release}&architecture={arch}&graphical={graphical}&type={type_list}", page),
            "counts": pager.counts(page),
            "length": len(rpms),
            "config": data_config,
            "base_url": "/list",
            "url_end": f"?distribution={release}&architecture={arch}&graphical={graphical}",     
            "nav_html": nav_data["html"],
            "nav_css": nav_data["css"],
        }
        return render_template("packages_list.html", data=data)

    @app.route("/tools/updates/")
    def old_updates():
        return redirect("/updates/")
    @app.route("/updates/")
    def updates():
        data_bugs, releases, counts = BugsList().qa_updates()
        for version in releases:
            data_bugs[version] = sorted(
                data_bugs[version],
                key=lambda item: item["severity_weight"],
                reverse=True,
            )
        nav_data = navbar(lang=request.accept_languages.best)
        data = {
            "bugs": data_bugs,
            "releases": releases,
            "counts": counts,
            "config": data_config,
            "nav_html": nav_data["html"],
            "nav_css": nav_data["css"],
        }
        return render_template("updates.html", data=data)

    @app.route("/tools/blockers/")
    def old_blockers():
        return redirect("/blockers/")
    @app.route("/blockers/")
    def blockers():
        urls = {}
        created, status_open, closed, column, param_csv = format_bugs()
        column_full = [("columnlist", column)]
        column_short = [("columnlist", "bug_id")]
        params = {}
        nav_data = navbar(lang=request.accept_languages.best)
        params_base = status_open + [
            ("human", "1"),
            ("priority", "release_blocker"),
            ("query_format", "advanced"),
        ]
        params["demoted"] = status_open + [
            ("j_top", "AND_G"),
            ("f1", "priority"),
            ("o1", "changedafter"),
            ("o2", "changedfrom"),
            ("query_format", "advanced"),
            ("f2", "priority"),
            ("v1", "2w"),
            ("v2", "release_blocker"),
        ]
        params["closed"] = [
            ("priority", "release_blocker"),
        ] + closed
        params["promoted"] = params_base + [
            ("chfieldto", "Now"),
            ("chfield", "priority"),
            ("chfieldfrom", "2w"),
            ("chfieldvalue", "release_blocker"),
            ("f1", "creation_ts"),
            ("o1", "lessthan"),
            ("v1", "2w"),
        ]
        counts = {}
        params["created"] = params_base + created
        for status in ("closed", "created", "promoted", "demoted"):
            a = requests.get(URL, params=params[status] + param_csv + column_short)
            urls[status] = URL + "?" + parse.urlencode(params[status] + column_full)
            counts[status] = len(a.content.split(b"\n")) - 1
        data_bugs, counts["base"], assignees = list_bugs(
            params_base + param_csv + column_full
        )
        title = "Current Blockers"
        comments = """This page lists all bug reports that have been marked as release blockers, which means that
        they must be fixed before the next release of Mageia. The <strong>bug watcher</strong>
        (QA contact field in bugzilla) is someone who commits to update the <strong>bug status comment</strong>
        regularly and tries to get a status from the packagers involved and remind them about the bug if needed.
        <strong>Anyone</strong> can be bug watcher."""
        nav_data = navbar(lang=request.accept_languages.best)
        data = {
            "urls": urls,
            "counts": counts,
            "bugs": data_bugs,
            "assignees": assignees,
            "config": data_config,
            "title": title,
            "comments": comments,
            "nav_html": nav_data["html"],
            "nav_css": nav_data["css"],
        }
        return render_template("bugs.html", data=data)

    @app.route("/tools/milestone/")
    def old_milestone():
        return redirect("/milestone/")
    @app.route("/milestone/")
    def milestone():
        urls = {}
        counts = {}
        params = {}
        nav_data = navbar(lang=request.accept_languages.best)
        created, status_open, closed, column, param_csv = format_bugs()
        column_full = [("columnlist", column)]
        column_short = [("columnlist", "bug_id")]
        params_base = [
            ("priority", "High"),
            ("priority", "Normal"),
            ("priority", "Low"),
            ("target_milestone", f"Mageia {data_config['Next']}"),
        ]
        params["closed"] = params_base + closed
        params["created"] = params_base + created + status_open
        params["promoted"] = (
            params_base
            + status_open
            + [
                ("chfield", "target_milestone"),
                ("chfieldfrom", "2w"),
                ("chfieldvalue", f"Mageia {data_config['Next']}"),
                ("chfieldto", "Now"),
                ("f1", "creation_ts"),
                ("o1", "lessthan"),
                ("v1", "2w"),
            ]
        )
        params["demoted"] = (
            params_base
            + status_open
            + [
                ("j_top", "AND_G"),
                ("f1", "target_milestone"),
                ("o1", "changedfrom"),
                ("o2", "changedafter"),
                ("chfieldto", "Now"),
                ("query_format", "advanced"),
                ("chfieldfrom", "2w"),
                ("f2", "target_milestone"),
                ("v1", f"Mageia {data_config['Next']}"),
                ("v2", "2w"),
            ]
        )
        for status in ("closed", "created", "promoted", "demoted"):
            a = requests.get(URL, params=params[status] + param_csv + column_short)
            urls[status] = URL + "?" + parse.urlencode(params[status] + column_full)
            counts[status] = len(a.content.split(b"\n")) - 1
        data_bugs, counts["base"], assignees = list_bugs(
            params_base + status_open + param_csv + column_full
        )
        title = "Intended for next release, except blockers"
        comments = """This page lists all bug reports that have been marked as intented for next release, except release blockers.
        The <strong>bug watcher</strong> (QA contact field in bugzilla) is someone who commits to update the <strong>bug status comment</strong>
        regularly and tries to get a status from the packagers involved and remind them about the bug if needed.
        <strong>Anyone</strong> can be bug watcher."""
        nav_data = navbar(lang=request.accept_languages.best)
        data = {
            "urls": urls,
            "counts": counts,
            "bugs": data_bugs,
            "assignees": assignees,
            "config": data_config,
            "title": title,
            "comments": comments,
            "nav_html": nav_data["html"],
            "nav_css": nav_data["css"],
        }
        return render_template("bugs.html", data=data)

    @app.route("/rpmsforqa/<bug_number>")
    def rpmsforqa(bug_number):
        raw = request.args.get("raw", 0)
        report = BugReport()
        # load data
        report.from_number(bug_number)
        releases = report.get_releases()
        data = {}
        nav_data = navbar(lang=request.accept_languages.best)
        for release in releases:
            if "release" not in data.keys():
                        data[release] = {}
            srpms =  report.get_srpms(release)
            distro = {}
            for src_arch in ("x86_64", "i586"):
                data[release][src_arch] = {}
                distro[src_arch] = Dnf5MadbBase(release, src_arch, config.DATA_PATH)
                data[release][src_arch]["srpms"] = distro[src_arch].search_name(srpms, repo=f"{release}-SRPMS-*testing*")
                # Get all binaries rpms having the source in the provided list
                binaries = distro[src_arch].search_by_sources(
                    [f"{x.get_name()}-{x.get_evr()}*" for x in data[release][src_arch]["srpms"]],
                    repo=f"{release}-*testing*"
                    )
                # order binaries by repo
                data[release][src_arch]["binaries"] = {}
                for repo in set([x.get_repo_id() for x in binaries]):
                    data[release][src_arch]["binaries"][repo] = []
                for binary in binaries:
                    label = binary.get_name() + "-" + binary.get_version() + "-" + binary.get_release()
                    data[release][src_arch]["binaries"][binary.get_repo_id()].append(label)
        data["config"] = data_config
        data["releases"] = releases 
        data["title"] = "Packages for bug report {num}".format(num=bug_number)
        data["number"] = bug_number
        if raw:
            text_file = render_template("rpms_for_qa_raw.html", data=data)
            return Response(text_file,
                    mimetype='text/plain',
                    headers={'Content-disposition': f'attachment; filename=r{bug_number}.txt'})

        else:
            return render_template("rpms_for_qa.html", data=data)

    @app.route("/tools/highpriority/")
    def old_highpriority():
        return redirect("/highpriority/")
    @app.route("/highpriority/")
    def highpriority():
        urls = {}
        counts = {}
        params = {}
        created, status_open, closed, column, param_csv = format_bugs()
        column_full = [("columnlist", column)]
        column_short = [("columnlist", "bug_id")]
        params_base = [
            ("priority", "High"),
            ("f1", "target_milestone"),
            ("o1", "notequals"),
            ("o2", "notequals"),
            ("query_format", "advanced"),
            ("f2", "target_milestone"),
            ("version", "Cauldron"),
            ("v1", f"Mageia {data_config['Next']}"),
            ("v2", f"Mageia {data_config['Next'] + 1}"),
        ]
        params["closed"] = params_base + closed
        params["created"] = params_base + created + status_open
        params["promoted"] = [
            ("chfieldto", "Now"),
            ("chfield", "priority"),
            ("chfieldfrom", "2w"),
            ("chfieldvalue", "High"),
            ("f5", "creation_ts"),
            ("o5", "lessthan"),
            ("v5", "2w"),
        ]
        params["demoted"] = status_open + [
            ("priority", "Normal"),
            ("priority", "Low"),
            ("j_top", "AND_G"),
            ("f1", "priority"),
            ("o1", "changedafter"),
            ("v1", "2w"),
            ("query_format", "advanced"),
            ("f3", "priority"),
            ("f2", "priority"),
            ("o2", "changedfrom"),
            ("version", "Cauldron"),
            ("v2", "High"),
        ]
        for status in ("closed", "created", "promoted", "demoted"):
            a = requests.get(URL, params=params[status] + param_csv + column_short)
            urls[status] = URL + "?" + parse.urlencode(params[status] + column_full)
            counts[status] = len(a.content.split(b"\n")) - 1
        data_bugs, counts["base"], assignees = list_bugs(
            params_base + status_open + param_csv + column_full
        )
        title = "High Priority Bugs for next release, except those already having a milestone set."
        comments = """This page lists all bug reports that have been marked with a high priority (except bugs with a milestone, which are already present in the "Intended for..." page).
    The <strong>bug watcher</strong>
    (QA contact field in bugzilla) is someone who commits to update the <strong>bug status comment</strong>
    regularly and tries to get a status from the packagers involved and remind them about the bug if needed.
    <strong>Anyone</strong> can be bug watcher."""
        nav_data = navbar(lang=request.accept_languages.best)
        data = {
            "urls": urls,
            "counts": counts,
            "bugs": data_bugs,
            "assignees": assignees,
            "config": data_config,
            "title": title,
            "comments": comments,
            "nav_html": nav_data["html"],
            "nav_css": nav_data["css"],
        }
        return render_template("bugs.html", data=data)


    @app.route("/tools/mageiatools/")
    def old_mageiatools():
        return redirect("/mageiatools/")
    @app.route("/mageiatools/")
    def mageiatools():
        urls = {}
        counts = {}
        params = {}
        created, status_open, closed, column, param_csv = format_bugs()
        column_full = [("columnlist", column)]
        column_short = [("columnlist", "bug_id")]
        params_base = [
            ("priority", "High"),
            ("priority", "Normal"),
            ("priority", "Low"),
            ("email1", "mageiatools@ml.mageia.org"),
            ("emailassigned_to1",1),
            ("emailtype1", "substring")
        ]
        params["closed"] = params_base + closed
        params["created"] = params_base + created + status_open
        params["promoted"] = (
            params_base
            + status_open
            + [
                ("chfield", "assigned_to"),
                ("chfieldfrom", "2w"),
                ("chfieldvalue", "mageiatools@ml.mageia.org"),
                ("chfieldto", "Now"),
                ("f1", "creation_ts"),
                ("o1", "lessthan"),
                ("v1", "2w"),
            ]
        )
        params["demoted"] = (
            params_base
            + status_open
            + [
                ("j_top", "AND_G"),
                ("f1", "assigned_to"),
                ("o1", "changedfrom"),
                ("o2", "changedafter"),
                ("chfieldto", "Now"),
                ("query_format", "advanced"),
                ("chfieldfrom", "2w"),
                ("f2", "email1"),
                ("v1", "mageiatools@ml.mageia.org"),
                ("v2", "2w"),
            ]
        )
        for status in ("closed", "created", "promoted", "demoted"):
            a = requests.get(URL, params=params[status] + param_csv + column_short)
            urls[status] = URL + "?" + parse.urlencode(params[status] + column_full)
            counts[status] = len(a.content.split(b"\n")) - 1
        data_bugs, counts["base"], assignees = list_bugs(
            params_base + status_open + param_csv + column_full
        )
        title = "About Mageia tools"
        comments = """This page lists all bug reports that have been assigned to Mageia tools maintainers.
        """
        nav_data = navbar(lang=request.accept_languages.best)
        data = {
            "urls": urls,
            "counts": counts,
            "bugs": data_bugs,
            "assignees": assignees,
            "config": data_config,
            "title": title,
            "comments": comments,
            "nav_html": nav_data["html"],
            "nav_css": nav_data["css"],
        }
        return render_template("bugs.html", data=data)

    @app.route("/group")
    def group():
        release = request.args.get("distribution", None)
        arch = request.args.get("architecture", None)
        req_group = request.args.get("group", None)
        graphical = request.args.get("graphical", "0")
        nav_data = navbar(lang=request.accept_languages.best)
        if not release:
            release = next(iter(config.DISTRIBUTION.keys()))
            arch = next(iter(config.ARCHES.keys()))
        if req_group is not None:
            level = len(req_group.split("/"))
            matches = [grp for grp in groups() if "/".join(grp).startswith(req_group)]
        else:
            level = 0
            matches = groups()
        if len(matches) > 1:
            # this is not a leaf group
            data = {
                "config": data_config,
                "title": "By group",
                "topic": f"Subgroups of {req_group}" if req_group else "Main groups",
                "req_group": req_group,
                "groups": sorted(set([ match[level] for match in matches])),
                "url_end": f"?distribution={release}&architecture={arch}&graphical={graphical}",
                "base_url": "/group",
                "group": req_group,
                "nav_html": nav_data["html"],
                "nav_css": nav_data["css"],
            }
            return render_template("group.html", data=data)

        distro = Dnf5MadbBase(release, arch, config.DATA_PATH)
        rpms_list = distro.search_in_group(req_group, graphical=graphical)
        if not rpms_list:
            rpms_list = {}
        data = {
            "config": data_config,
            "title": "By group",
            "topic": f"Group: {req_group}",
            "rpms": rpms_list,
            "url_end": f"?distribution={release}&architecture={arch}&graphical={graphical}",
            "base_url": "/group",
            "group": req_group,
            "nav_html": nav_data["html"],
            "nav_css": nav_data["css"],
        }
        return render_template("package_list.html", data=data)

    @app.route("/show")
    def show():
        release = request.args.get("distribution", None)
        arch = request.args.get("architecture", None)
        package = request.args.get("rpm", "")
        graphical = request.args.get("graphical", "0")
        distro = Dnf5MadbBase(release, arch, config.DATA_PATH)
        dnf_pkgs = distro.search_name([package], graphical=(graphical == "1"))
        rpms = []
        last = None
        nav_data = navbar(lang=request.accept_languages.best)
        for dnf_pkg in dnf_pkgs:
            rpms.append(
                {
                    "full_name": dnf_pkg.get_nevra(),
                    "distro_release": release,
                    "url": f"/rpmshow?rpm={dnf_pkg.get_name()}&repo={dnf_pkg.get_repo_id()}&distribution={release}&architecture={arch}&graphical={graphical}",
                    "arch": dnf_pkg.get_arch(),
                    "repo": dnf_pkg.get_repo_name(),
                }
            )
            last = dnf_pkg
        if last is not None:
            sc = Screenshots()
            links = sc.image_links(last.get_name())
            first_sc = None
            if links is not None and len(links) != 0:
                first_sc = links[0]
            pkg = {
                "name": last.get_name(),
                "rpms": rpms,
                "license": last.get_license(),
                "summary": last.get_summary(),
                "description": last.get_description(),
                "url": last.get_url(),
                "maintainer": last.get_packager(),
                "screenshot": first_sc,
                "other_screenshots": links,
            }
        else:
            data = {
                "title": "Not found",
                "config": data_config,
                "url_end": f"/{release}/{arch}/{graphical}",
                "base_url": "/home",
                "rpm_search": "",
                "url_end": f"?distribution={release}&architecture={arch}&graphical={graphical}",
                "nav_html": nav_data["html"],
                "nav_css": nav_data["css"],
            }
            return render_template("notfound.html", data=data)
        data = {
            "pkg": pkg,
            "config": data_config,
            "url_end": f"?distribution={release}&architecture={arch}&graphical={graphical}",
            "rpm_search": package,
            "base_url": "/show",
            "nav_html": nav_data["html"],
            "nav_css": nav_data["css"],
        }
        return render_template("package_show.html", data=data)

    @app.route("/rpmshow")
    def rpmshow():
        release = request.args.get("distribution", None)
        arch = request.args.get("architecture", None)
        graphical = request.args.get("graphical", "1")
        package = request.args.get("rpm", "")
        repo = request.args.get("repo", "")
        nav_data = navbar(lang=request.accept_languages.best)
        if package == "" or repo == "":
            data = {
                "title": "Not found",
                "config": data_config,
                "url_end": f"/{release}/{arch}/{graphical}",
                "base_url": "/home",
                "rpm_search": "",
                "url_end": f"?distribution={release}&architecture={arch}&graphical={graphical}",
            }
            return render_template("notfound.html", data=data)
        distro = Dnf5MadbBase(release, arch, config.DATA_PATH)
        dnf_pkgs = distro.search_name([package], repo=repo)
        rpms = []
        last = None
        for dnf_pkg in dnf_pkgs:
            rpms.append(
                {
                    "full_name": dnf_pkg.get_nevra(),
                    "distro_release": release,
                    "arch": dnf_pkg.get_arch(),
                    "repo": dnf_pkg.get_repo_name(),
                }
            )
            last = dnf_pkg
        if last is not None:
            basic = {
                "Name": last.get_name(),
                "Version": last.get_version(),
                "Release": last.get_release(),
                "Arch": last.get_arch(),
                "Summary": last.get_summary(),
                "Group": last.get_group(),
                "License": last.get_license(),
                "Url": last.get_url(),
                "Download size": humanize.naturalsize(
                    last.get_download_size(), binary=True
                ),
                "Installed size": humanize.naturalsize(
                    last.get_install_size(), binary=True
                ),
            }
            description = last.get_description()
            rpm = last.get_nevra()
            media = [
                ["Repository name", last.get_repo_name()],
                ["Media arch", arch],
            ]
            deps = []
            reqs = last.get_requires()
            for item in distro.provides_requires(reqs):
                if not item.get_name() in deps:
                    deps.append(item.get_name())
            logs = []
            for item in last.get_changelogs():
                logs.append(
                    f"{date.fromtimestamp(item.timestamp)}:<br /> {item.text} <br />({item.author})"
                )
            advanced = [
                ["Source RPM", last.get_sourcerpm() or "NOT IN DATABASE ?!", ""],
                ["Build time", datetime.fromtimestamp(last.get_build_time()), ""],
                ["Dependencies graph", f"<a href='/graph?distribution={release}&architecture={arch}&rpm={last.get_name()}'>Open</a>", ""],
                ["Changelog", "<br />\n".join(logs), ""],
                ["Files", "<br />\n".join(last.get_files()), ""],
                ["Dependencies", "<br />\n".join(deps), ""],
                ["Provides", "<br />\n".join([x.get_name() for x in last.get_provides()]), ""],
            ]
        else:
            data = {
                "title": "Not found",
                "config": data_config,
                "url_end": f"/{release}/{arch}/{graphical}",
                "base_url": "/home",
                "rpm_search": "",
                "url_end": f"?distribution={release}&architecture={arch}&graphical={graphical}",
                "nav_html": nav_data["html"],
                "nav_css": nav_data["css"],
            }
            return render_template("notfound.html", data=data)
        data = {
            "basic": basic,
            "config": data_config,
            "advanced": advanced,
            "repo": repo,
            "media": media,
            "description": description,
            "rpm_search": package,
            "base_url": "/rpmshow",
            "url_end": f"?distribution={release}&architecture={arch}&graphical={graphical}&rpm={package}",
            "nav_html": nav_data["html"],
            "nav_css": nav_data["css"],
        }
        return render_template("rpm_show.html", data=data)

    @app.route("/tools/comparison")
    def old_comparison():
        return redirect("/comparison")
    @app.route("/comparison")
    def comparison():
        repo_classes = ('release', 'updates', 'updates_testing', 'backports', 'backports_testing')
        def merge_summaries(rpm):
            if pd.isnull(rpm["Summaryrelease"]):
                keys = rpm.keys()
                for cl in repo_classes:
                    key = "Summarydev" + cl
                    if key in keys and not pd.isnull(key):
                        return rpm["Summarydev"+cl]
                return ""
            else:
                return rpm["Summaryrelease"]

        def versions_compare(rpm):
            v_dev = {}
            v_stable = {}
            new = True
            old = False
            testing = False 
            backported = False
            dropped = True
            updated = False
            for cl in repo_classes:
                key_dev = label_dev[cl]
                if key_dev in rpm.keys() and not pd.isnull(rpm[key_dev]):
                    dropped = False
                    try:
                        v_dev[cl] = pvers.Version(rpm[key_dev])
                    except:
                        return ""
                if label[cl] in rpm.keys():
                    if not pd.isnull(rpm[label[cl]]) :
                        try:
                            v_stable[cl] = pvers.Version(rpm[label[cl]])
                            if "testing" in cl:
                                testing = testing or (v_stable[cl] == v_dev["release"])
                            if "backport" in cl and v_stable[cl] == v_dev[ "release"]:
                                backported = True
                        except:
                            return ""
                        if cl == "updates":
                            v_stable["release"] = v_stable[cl]
                        # check if package is new in dev
                        new = False
                        if v_dev != {} and not new:
                            old = old or (v_dev["release"] < v_stable[cl])
                            updated = updated or (v_dev["release"] > v_stable[cl])
            if new:
                # added in dev
                return "newpackage"
            if old:
                # version in dev is older
                return "older"
            if testing:
                # being tested and same version in dev
                return "testing"
            if backported:
                return "backported"
            if updated:
                # version in dev is newer
                return "updated"
            if dropped:
                return "dropped"

        def really_dropped(rpm):
            if rpm["classes"] == "dropped" and graphical == "1":
                dev = list(distro2.search_name([rpm.name], repo= "*release*"))
                if len(dev) != 0:
                    return dev[0].get_version()
                return pd.NA
            else:
                return rpm[label_dev["release"]]

        def really_dropped_classes(rpm):
            if rpm["classes"] == "dropped" and graphical == "1":
                dev = list(distro2.search_name([rpm.name], repo= "*release*"))
                if len(dev) != 0:
                    return versions_compare(rpm)
                return  "dropped"
            else:
                return rpm["classes"]

        release = request.args.get("distribution", str(config.TOP_RELEASE))
        arch = request.args.get("architecture", "x86_64")
        graphical = request.args.get("graphical", "1")
        page = request.args.get("page", "A", type = str)
        distro1 = Dnf5MadbBase(release, arch, config.DATA_PATH)
        distro2 = Dnf5MadbBase(config.DEV_NAME, arch, config.DATA_PATH)
        rpms_temp = {}
        rpms_dev_temp = {}
        label = {}
        label_dev = {}
        label["release"] = f"Stable {release}"
        label["updates"] = f"Update {release}"
        label["updates_testing"] = "Update candidate"
        label["backports"] = "Backport"
        label["backports_testing"] = "Backport candidate"
        label_dev["release"] = f"{config.DISTRIBUTION[config.DEV_NAME]}"
        label_dev["updates"] = f"Update {config.DISTRIBUTION[config.DEV_NAME]}"
        label_dev["updates_testing"] = f"{config.DISTRIBUTION[config.DEV_NAME]} Update candidate"
        label_dev["backports"] = f"{config.DISTRIBUTION[config.DEV_NAME]} Backport"
        label_dev["backports_testing"] = f"{config.DISTRIBUTION[config.DEV_NAME]} Backport candidate"
        # search packages with name starting by a number or specified character
        if page == "0":
            criteria = [str(i) + "*" for i in range(0, 10)]
        else:
            criteria = [page + "*", page.lower() + "*"]
        for cl in repo_classes:
            rpms_temp[cl] = {x.get_name():{
            "Summary"+cl: x.get_summary(),
            label[cl]: x.get_version(),
            } for x in distro1.search([], criteria, graphical=(graphical == "1"), repo=f"{release}-{arch}-*-{cl}")}
            rpms1 = pd.DataFrame(rpms_temp[cl])
            if cl == "release":
                rpms = rpms1
            else:
                rpms = pd.concat([rpms, rpms1])
        for cl in repo_classes:
            rpms_dev_temp[cl] = {
                x.get_name():{
                    "Summarydev"+cl: x.get_summary(),
                    label_dev[cl]: x.get_version(),
                    }
                for x in distro2.search([], criteria, graphical=(graphical == "1"), repo=f"{config.DEV_NAME}-{arch}-*-{cl}")}
            rpms2 = pd.DataFrame(rpms_dev_temp[cl])
            rpms = pd.concat([rpms, rpms2])
        # determine classes
        rpms.loc["classes"] = rpms.apply(lambda x : versions_compare(x), axis=0)
        # fix false dropped if graphical has changed
        rpms.loc[label_dev["release"]] = rpms.apply(really_dropped)
        rpms.loc["classes"] = rpms.apply(really_dropped_classes)
        # merge column Summary
        rpms.loc["Summaryrelease"] = rpms.apply(lambda x : merge_summaries(x), axis=0)
        # remove NaN content
        rpms.where(pd.notna, "", inplace=True)
        # sort by package names
        rpms.sort_index(axis=1, inplace=True)
        pager = Pagination(list(rpms.index), byfirstchar=True)
        nav_data = navbar(lang=request.accept_languages.best)
        data = {
            "rpms": rpms,
            "links": pager.links_by_char(f"/comparison?distribution={release}&architecture={arch}&graphical={graphical}", page),
            "release": release,
            "arch": arch,
            "rel": data_config["distribution"][release],
            "url_end": f"?distribution={release}&architecture={arch}&graphical={graphical}",  # used for setting the search fields
            "config": data_config,
        }
        return render_template("comparison.html", data=data)

    def format_bugs():
        column = ",".join(
            [
                "product",
                "component",
                "bug_status",
                "short_desc",
                "changeddate",
                "cf_statuscomment",
                "qa_contact_realname",
                "priority",
                "bug_severity",
                "cf_rpmpkg",
                "assigned_to_realname",
                "bug_id",
                "assigned_to",
            ]
        )
        created = [
            ("chfield", "[Bug creation]"),
            ("chfieldfrom", "2w"),
            ("chfieldto", "Now"),
        ]
        status_open = [
            ("bug_status", "NEW"),
            ("bug_status", "UNCONFIRMED"),
            ("bug_status", "ASSIGNED"),
            ("bug_status", "REOPENED"),
        ]
        closed = [
            ("chfieldto", "Now"),
            ("query_format", "advanced"),
            ("chfield", "bug_status"),
            ("chfieldfrom", "2w"),
            ("chfieldvalue", "RESOLVED"),
            ("bug_status", "RESOLVED"),
            ("bug_status", "VERIFIED"),
        ]
        param_csv = [("ctype", "csv"), ("human", "1")]
        return created, status_open, closed, column, param_csv

    def list_bugs(params):
        a = requests.get(URL, params=params)
        content = a.content.decode("utf-8")
        bugs = DictReader(StringIO(content))
        assignees = []
        now = datetime.now()
        data_bugs = {}
        counts = 0
        for bug in bugs:
            counts += 1
            entry = bug
            assignee = bug["Assignee Real Name"]
            assignee_names = [x["name"] for x in assignees]
            if assignee in assignee_names:
                assignees[assignee_names.index(assignee)]["bugs"] += (bug["Bug ID"],)
            else:
                mefirst = 1
                for word in ("team", "group", "packagers", "maintainer"):
                    if word in assignee.lower():
                        mefirst = 0
                        break
                assignee_bug = (bug["Bug ID"],)
                assignees.append(
                    {"name": assignee, "bugs": assignee_bug, "order": mefirst}
                )
            entry["age"] = (now - datetime.fromisoformat(bug["Changed"])).days
            data_bugs[bug["Bug ID"]] = entry
        return data_bugs, counts, assignees

    @app.route("/graph")
    def graph():
        release = request.args.get("distribution", None)
        arch = request.args.get("architecture", None)
        pkg = request.args.get("rpm", "dnf")
        level = request.args.get("level", 2, type=int)
        descending = request.args.get("descending", 1, type=int)
        if not release:
            release = next(iter(config.DISTRIBUTION.keys()))
            arch = next(iter(config.ARCHES.keys()))
        nav_data = navbar(lang=request.accept_languages.best)
        data = {
            "nav_html": nav_data["html"],
            "nav_css": nav_data["css"],
            "config": data_config,
            "title": f"Network of packages required  by {pkg}" if descending else f"Network of packages which require {pkg}",
            "base_url" : "/graph",
            "graph": True,
            "level": level,
            "rpm_search": pkg,
            "descending": descending,
            "url_end": f"?distribution={release}&architecture={arch}&graphical=0",
        }
        graph = RpmGraph(release, arch, level, descending)
            
        # Get Chart Components 
        graph_run = graph.render_vis(pkg)
        if graph_run is None:
            return render_template( 
                template_name_or_list='notfound.html', 
                data = data
                ) 
        # script, content = components(graph_run)
        graph_run.save_graph("/tmp/graph.html")

        # We select all script, link, style from the head section, and script from body. We need <div id="mynetwork" class="card-body"></div> to place the graph.
        with open("/tmp/graph.html") as f:
            soup = BeautifulSoup(f.read(), 'html.parser')
            head = "\n".join([str(a) for a in soup.head.find_all(["script", "style", "link"])])
            body_script = head +"\n" + str(soup.body.script)
            body_script = body_script.replace("lib/","static/lib/")

        # Return the components to the HTML template 
        return render_template( 
            template_name_or_list='graph.html', 
            content=body_script,
            data=data
        ) 


    @app.template_filter()
    def format_date(timestamp):
        return datetime.fromtimestamp(timestamp).date()

    return app

if __name__ == "__main__":
    app.run(host="0.0.0.0")
