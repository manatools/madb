#!/usr/bin/env python3
from madb.helper import groups
from madb.helper import BugReport
from madb.helper import load_content_or_cache, clean_cache
from flask import Flask, render_template, request
import requests
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

logger = logging.getLogger(__name__)
log_level = getattr(logging, config.LOG_LEVEL.upper())
logging.basicConfig(filename=os.path.join(config.DATA_PATH,'madb.log'), encoding='utf-8', level=log_level)

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
        last_updates = distro.search_updates()
        if not last_updates:
            last_updates = {}
        last_backports = distro.search_updates(backports=True)
        if not last_backports:
            last_backports = {}
        groups1 = sorted(set([x[0] for x in groups()]))
        nav_data = navbar(lang=request.accept_languages.best)
        data = {
            "groups": groups1,
            "config": data_config,
            "title": "Home",
            "updates": last_updates,
            "backports": last_backports,
            "rpm_search": rpm,
            "url_end": f"?distribution={release}&architecture={arch}&graphical=0",
            "base_url": "/home",
            "nav_html": nav_data["html"],
            "nav_css": nav_data["css"],
        }
        return render_template("home.html", data=data)

    @app.route("/updates/")
    def updates():
        column = ",".join(
            [
                "bug_severity",
                "priority",
                "op_sys",
                "assigned_to",
                "bug_status",
                "resolution",
                "short_desc",
                "status_whiteboard",
                "keywords",
                "version",
                "cf_rpmpkg",
                "component",
                "changeddate",
            ]
        )
        params = [
            ("bug_status", "REOPENED"),
            ("bug_status", "NEW"),
            ("bug_status", "ASSIGNED"),
            ("bug_status", "UNCONFIRMED"),
            ("columnlist", column),
            ("field0-0-0", "assigned_to"),
            ("query_format", "advanced"),
            ("type0-0-0", "substring"),
            ("type1-0-0", "notsubstring"),
            ("value0-0-0", "qa-bugs"),
            ("ctype", "csv"),
        ]
        f = requests.get(URL, params=params)
        content = f.content.decode("utf-8")
        bugs = DictReader(StringIO(content))

        # bug_id,"bug_severity","priority","op_sys","assigned_to","bug_status","resolution","short_desc", "status_whiteboard","keywords","version","cf_rpmpkg","component","changeddate"
        releases = []
        temp_bugs = []
        severity_weight = {
            "enhancement": 0,
            "minor": 1,
            "normal": 2,
            "major": 3,
            "critical": 4,
        }
        for bug in bugs:
            # Error if cauldron, not conform to our policy
            entry = bug
            if entry["version"] not in releases:
                releases.append(entry["version"])
            wb = re.findall(r"\bMGA(\d+)TOO", entry["status_whiteboard"])
            for key in wb:
                if key not in releases:
                    releases.append(key)
            temp_bugs.append(entry)
        data_bugs = {}
        now = datetime.now()
        counts = {}
        for rel in releases:
            data_bugs[rel] = []
            counts[str] = []
            for entry in temp_bugs:
                entry["OK_64"] = ""
                entry["OK_32"] = ""
                if entry["version"] == "Cauldron":
                    # we skip it
                    versions_list = ()
                else:
                    versions_list = (entry["version"],)
                wb = re.findall(r"\bMGA(\d+)TOO", entry["status_whiteboard"])
                wbo = re.findall(r"\bMGA(\d+)-(\d+).OK", entry["status_whiteboard"])
                for v, a in wbo:
                    if a == "64":
                        entry["OK_64"] += f" {v}"
                    if a == "32":
                        entry["OK_32"] += f" {v}"
                    if v not in versions_list:
                        versions_list += (v,)
                # union of the 2 lists, without duplication
                versions = " ".join(wb + list(set(versions_list) - set(wb)))
                entry["versions_symbol"] = ""
                # Build field Versions
                for version in versions.split(" "):
                    OK_64 = version in entry["OK_64"]
                    OK_32 = version in entry["OK_32"]
                    full = OK_32 and OK_64
                    partial = (OK_32 and not OK_64) or (not OK_32 and OK_64)
                    not_tested = not OK_64 and not OK_32
                    if full:
                        testing_class = "testing_complete"
                        title = "Testing complete for both archs"
                        symbol = "⚈"
                    if partial:
                        testing_class = "testing_one_ok"
                        title = "Testing partial (at least one arch)"
                        symbol = "⚉"
                    if not_tested:
                        testing_class = "testing_not_ok"
                        title = "Testing not complete for any arch"
                        symbol = "⚈"
                    entry["versions_symbol"] = " ".join(
                        [
                            entry["versions_symbol"],
                            f'{version}<span class="{testing_class}" title= "{title}"><span>{symbol}</span></span>',
                        ]
                    )
                if rel in versions:
                    if entry["component"] != "Security":
                        entry["component"] = "Bugfix"
                    entry["age"] = (
                        now - datetime.fromisoformat(entry["changeddate"])
                    ).days
                    entry["versions"] = versions
                    if "validated_backport" in entry["keywords"]:
                        entry["status"] = "validated_backport"
                    elif "validated_update" in entry["keywords"]:
                        entry["status"] = "validated_update"
                    elif "validated_" in entry["keywords"]:
                        entry["status"] = "pending"
                    else:
                        entry["status"] = "assigned"
                    tr_class = ""
                    entry["severity_weight"] = severity_weight[entry["bug_severity"]]
                    if (
                        entry["bug_severity"] == "enhancement"
                        or entry["component"] == "Backports"
                    ):
                        tr_class = "enhancement"
                        entry["severity_weight"] = severity_weight["enhancement"]
                    elif entry["bug_severity"] == "minor":
                        tr_class = "low"
                    elif (
                        entry["bug_severity"] in ("major", "critical")
                        and entry["component"] != "Security"
                    ):
                        tr_class = "major"
                    else:
                        tr_class = entry["bug_severity"]
                    if entry["component"] == "Security":
                        entry["severity_weight"] += 8
                    if "advisory" in entry["keywords"]:
                        entry["component"] += "*"
                    if "feedback" in entry["keywords"]:
                        tr_class = " ".join([tr_class, "feedback"])
                    entry["class"] = tr_class
                    data_bugs[rel].append(entry)
            counts[rel] = collections.Counter([x["status"] for x in data_bugs[rel]])
        for version in versions:
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
        report = BugReport()
        # load data
        report.from_number(bug_number)
        srpms =  [x + "*" for x in report.get_srpms()]
        releases = report.get_releases()
        data = {}
        nav_data = navbar(lang=request.accept_languages.best)
        for release in releases:
            if "release" not in data.keys():
                data[release] = {}
            distro = {}
            for src_arch in ("x86_64", "i586"):
                data[release][src_arch] = {}
                distro[src_arch] = Dnf5MadbBase(release, src_arch, config.DATA_PATH)
                data[release][src_arch]["srpms"] = distro[src_arch].search_name(srpms, repo=f"{release}-SRPMS-*testing*")
                # Get all binaries rpms having the source in the provided list
                binaries = distro[src_arch].search_by_sources(
                    [x.get_name() + "*" for x in data[release][src_arch]["srpms"]],
                    repo=f"{release}-*testing*"
                    )
                # order binaries by repo
                data[release][src_arch]["binaries"] = {}
                for repo in set([x.get_repo_id() for x in binaries]):
                    data[release][src_arch]["binaries"][repo] = []
                for binary in binaries:
                    data[release][src_arch]["binaries"][binary.get_repo_id()].append(binary.get_nevra())
        data["config"] = data_config
        data["releases"] = releases 
        data["title"] = "Packages for bug report {num}".format(num=bug_number)
        return render_template("rpms_for_qa.html", data=data)

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
            pkg = {
                "name": last.get_name(),
                "rpms": rpms,
                "license": last.get_license(),
                "summary": last.get_summary(),
                "description": last.get_description(),
                "url": last.get_url(),
                "maintainer": last.get_packager(),
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

    if __name__ == "__main__":
        app.run(host="0.0.0.0")

    return app
