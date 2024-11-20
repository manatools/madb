import re
import madb.config as config
import yaml
import requests
import hashlib
import os
import time
from itertools import chain
import string
from csv import DictReader
from io import StringIO
import collections
from datetime import datetime, timedelta, date

def groups():
    """
    Return a list of lists, each member being the parts of the group
    """
    grp = re.compile(r"'(.+)',")
    fin = re.compile(r"\)")
    list_grp = []
    with open(config.DEF_GROUPS_FILE, "r") as de:
        reading_group = False
        for line in de.readlines():
            if reading_group:
                m = grp.match(line.strip())
                if m:
                    list_grp.append(m.group(1).split("/"))
            if line.startswith("valid_groups=("):
                reading_group = True
    return list_grp

def advisories():
    pass
    #with open(, "r") as f:


CACHE_DIR = os.path.join(config.DATA_PATH, "cache")
LONG_CACHE_DIR = os.path.join(config.DATA_PATH, "cache/long")
CACHE_TTL = 60 * 60 * 24  # Cache expiration time: 1 day
LONG_CACHE_TTL = 60 * 60 * 24 * 100 # Cache expiration time: 100 days
CACHE_SIZE = 5
os.makedirs(CACHE_DIR, exist_ok=True)
os.makedirs(LONG_CACHE_DIR, exist_ok=True)

#  absolute path of cached file for specified URL
def _get_cache_filepath(url, long=True):
    filename = hashlib.sha256(url.encode("utf-8")).hexdigest()[:10]
    filepath = os.path.join(LONG_CACHE_DIR, filename) if long else os.path.join(CACHE_DIR, filename)
    return filepath

# Load cache content or from URL after expiration
def load_content_or_cache(url, long=True):
    filepath = _get_cache_filepath(url, long=long)
    ttl = LONG_CACHE_TTL if long else CACHE_TTL
    if not os.path.exists(filepath) or time.time() - os.path.getctime(filepath) > ttl:
        response = requests.get(url)
        with open(filepath, "w") as f:
            f.write(response.content.decode())
            print(f"Cache {filepath} wrotten")
    with open(filepath, "r") as f:
        content = f.read()
    return content

# Clean the cache
def clean_cache():
    time.sleep(10)
    while True:
        for cached_file in os.listdir(CACHE_DIR):
            if time.time() - os.path.getctime(os.path.join(CACHE_DIR, cached_file)) > CACHE_TTL:
                os.remove(cached_file)
        time.sleep(3600 * 24)

_column = ",".join(
        [
            "bug_severity",
            "priority",
            "assigned_to",
            "assigned_to_realname",
            "bug_status",
            "resolution",
            "short_desc",
            "status_whiteboard",
            "cf_statuscomment",
            "keywords",
            "version",
            "cf_rpmpkg",
            "component",
            "changeddate",
        ]
    )


class BugsList():

    def __init__(self):
        self.bugs = []

    def qa_updates(self):        
        params = [
                ("bug_status", "REOPENED"),
                ("bug_status", "NEW"),
                ("bug_status", "ASSIGNED"),
                ("bug_status", "UNCONFIRMED"),
                ("columnlist", _column),
                ("field0-0-0", "assigned_to"),
                ("query_format", "advanced"),
                ("type0-0-0", "substring"),
                ("type1-0-0", "notsubstring"),
                ("value0-0-0", "qa-bugs"),
                ("ctype", "csv"),
            ]
        return self._request(params)


    def security(self): 
        params = [
                ("bug_status", "REOPENED"),
                ("bug_status", "NEW"),
                ("bug_status", "ASSIGNED"),
                ("bug_status", "UNCONFIRMED"),
                ("columnlist", _column),
                ("component", "Security"),
                ("email1", "qa-bugs"),
                ("emailtype1", "notsubstring"),
                ("query_format", "advanced"),
                ("query_based_on", ""),
                ("ctype", "csv"),
            ]
        return self._request(params)

    def _request(self, params):
        f = requests.get(config.BUGZILLA_URL + "/buglist.cgi", params=params)
        content = f.content.decode("utf-8")
        bugs = DictReader(StringIO(content))

        releases = []
        temp_bugs = []
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
        
        self.bugs = {}
        counts = {}
        for rel in releases:
            self.bugs[rel] = []
            counts[rel] = []
            for entry in temp_bugs:
                bug = BugReport()
                bug.from_data(entry)
                self.bugs[rel].append(bug)
           # if rel != "unspecified":
                #print(rel)
                #for x in self.bugs[rel]:
                #    print(x.format_data(rel))
            counts[rel] = collections.Counter([x.data[rel]["status"] for x in self.bugs[rel] if rel in x.data.keys()])
        bugs_list = {}
        for rel in releases:
            bugs_list[rel] = []
            for bug in self.bugs[rel]:
                if rel in bug.data.keys():
                    bugs_list[rel].append(bug.data[rel])
        return bugs_list, releases, counts

class BugReport():
    column = _column

    severity_weight = {
            "enhancement": 0,
            "minor": 1,
            "normal": 2,
            "major": 3,
            "critical": 4,
        }

    def __init__(self):
        """
        data: Dict
        - releases: string, cited in the bug report in version field or in white board like MGA9TOO
        - srpms: set of strings, with the name of source packages

        """
        self.data = {}

    def from_number(self, number):
        self.number = number
        url = os.path.join(config.BUGZILLA_URL, "rest/bug", self.number)
        headers = {'Accept': 'application/json'}
        r = requests.get(url, params = [("include_fields", _column)], headers=headers)
        myjson = r.json()
        if r.status_code == 200 and myjson["faults"] == []:
            entry =  myjson['bugs'][0]
            for rel in self._releases(entry):
                self.data[rel] = entry
                # self.format_data(rel)

    def _releases(self, entry):
        result = {}
        versions_list = (entry["version"],)
        if "status_whiteboard" in entry.keys():
            wb = re.findall(r"\bMGA(\d+)TOO", entry["status_whiteboard"])
            wbo = re.findall(r"\bMGA(\d+)-(\d+).OK", entry["status_whiteboard"])
            for v, a in wbo:
                if v not in versions_list:
                    versions_list += (v,)
            # union of the 2 lists, without duplication
            versions_list = wb + list(set(versions_list) - set(wb))
        return versions_list

    def get_releases(self):
        return list(self.data.keys())

    def from_data(self, entry):
        self.number = entry["bug_id"]
        for rel in self._releases(entry):
            self.data[rel] = entry
            self.format_data(rel)
        if self.data == {}:
            print(f"no release for {self.number}")

    def format_data(self, rel):
        self.data[rel]["OK_64"] = ""
        self.data[rel]["OK_32"] = ""
        if "status_whiteboard" in self.data[rel].keys():
            wbo = re.findall(r"\bMGA(\d+)-(\d+).OK", self.data[rel]["status_whiteboard"])
            for v, a in wbo:
                if a == "64":
                    self.data[rel]["OK_64"] += f" {v}"
                if a == "32":
                    self.data[rel]["OK_32"] += f" {v}"
        if  rel not in self.data.keys():
            return {"status": "unspecified", "severity_weight": 0}
        if type(rel) == "int":
            rel = str(rel)
        self.data[rel]["versions_symbol"] = ""
        # Build field Versions
        releases = self._releases(self.data[rel])
        now = datetime.now()
        for version in releases:
            OK_64 = version in self.data[rel]["OK_64"]
            OK_32 = version in self.data[rel]["OK_32"]
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
            self.data[rel]["versions_symbol"] = " ".join(
                [
                    self.data[rel]["versions_symbol"],
                    f'{version}<span class="{testing_class}" title= "{title}"><span>{symbol}</span></span>',
                ]
            )
        if rel in releases:
            if self.data[rel]["component"] == "Security":
                self.data[rel]["severity_class"] = "security"
            elif self.data[rel]["component"] == "Backports":
                self.data[rel]["severity_class"] = "backport"
            elif self.data[rel]["bug_severity"] == "enhancement":
                self.data[rel]["severity_class"] = "enhancement"
            else:
                self.data[rel]["severity_class"] = "bugfix"
            self.data[rel]["age"] = (
                now - datetime.fromisoformat(self.data[rel]["changeddate"])
            ).days
            self.data[rel]["versions"] = releases
            if "validated_backport" in self.data[rel]["keywords"]:
                self.data[rel]["status"] = "validated_backport"
            elif "validated_update" in self.data[rel]["keywords"]:
                self.data[rel]["status"] = "validated_update"
            elif "validated_" in self.data[rel]["keywords"]:
                self.data[rel]["status"] = "pending"
            else:
                self.data[rel]["status"] = "assigned"
            tr_class = ""
            self.data[rel]["severity_weight"] = self.severity_weight[self.data[rel]["bug_severity"]]
            if (
                self.data[rel]["bug_severity"] == "enhancement"
                or self.data[rel]["severity_class"] == "backport"
            ):
                tr_class = "enhancement"
                self.data[rel]["severity_weight"] = self.severity_weight["enhancement"]
            elif self.data[rel]["bug_severity"] == "minor":
                tr_class = "low"
            elif (
                self.data[rel]["bug_severity"] in ("major", "critical")
                and self.data[rel]["severity_class"] != "security"
            ):
                tr_class = "major"
            else:
                tr_class = self.data[rel]["bug_severity"]
            if self.data[rel]["severity_class"] == "security":
                self.data[rel]["severity_weight"] += 8
            if "advisory" in self.data[rel]["keywords"]:
                self.data[rel]["severity_class"] += "*"
            if "feedback" in self.data[rel]["keywords"]:
                tr_class = " ".join([tr_class, "feedback"])
            self.data[rel]["class"] = tr_class
            self.data[rel]["srpms"] = self._srpms(self.data[rel]["cf_rpmpkg"])
        return self.data[rel]

    def get_srpms(self, release):
        """
        Return a set with the names of source packages
        """
        if "cf_rpmpkg" in self.data[release].keys():
            return self._srpms(self.data[release]['cf_rpmpkg'])
        return []

    def _srpms(self, field):
        """
        Return a set with the names of source packages
        """
        return [srpm.strip() for srpm in re.split(';|,| ', field) if srpm.strip() != ""]

class Pagination():
    def __init__(self, data, page_size=0, pages_number=0, byweek=False, byfirstchar=False):
        """
        Pages number is starting from 1
        Only one of page_size, pages_number, byweek or byfirstchar has to be set
        If byweek is True, data are truncated in pages by week of build time, from more recent to older
        If byfirstchar is True, data are truncated by the first character or grouping the numbers, represented by zero
        rpm index in data starts from 0
        """
        self.data = data
        self.byweek = byweek
        self.byfirstchar = byfirstchar
        self.lentgh = len(data)
        if pages_number != 0:
            self.page_size = (self.lentgh - 1) // pages_number + 1
            self.pages_max = pages_number
        elif page_size != 0:
            self.page_size = page_size
            self.pages_max = (self.lentgh - 1) // page_size + 1
        elif byweek:
            self._w_start = []
            self._w_end = []
            self._weeks = []
            now = int(time.time()) # in seconds
            previous = now - 7 * 24 * 3600 # in seconds
            i = 0
            self._w_start.append(0)
            first = True
            for rpm in data:
                bt = int(rpm.get_build_time())
                if first:
                    previous = bt - 7* 24 * 3600
                    first = False
                    self._weeks.append((now - bt) // (7* 24 * 3600))
                elif bt < previous:
                    previous = bt - 7* 24 * 3600
                    self._w_end.append(i - 1)
                    self._w_start.append(i)
                    self._weeks.append((now - bt) // (7* 24 * 3600))
                i += 1

            if i == 0:
                self.pages_max = 1
                self._w_end.append(0)
                self._w_start.append(0)
                self._weeks.append(1)
            else:
                self._w_end.append(i - 1)
                older = min([rpm.get_build_time() for rpm in data])
                self.pages_max = len(self._w_start)
        elif byfirstchar:
            self._char_list = ["0"] + list(string.ascii_uppercase)

    def data_page(self, page):
        if page >= 1 and page <= self.pages_max:
            return self.data[self._start(page):self._end(page) + 1]
    
    def links(self, base, page):
        pages_list =chain(range(1, 2) , \
            range(10, page + 1, 10), \
            range(max(2, page // 10 * 10 + 1), min((page //10) * 10 + 10, self.pages_max )), \
            range((page + 10) // 10 * 10 , self.pages_max, 10), \
            range(self.pages_max, self.pages_max + 1))
        full_links = """
    <div id="pagerbuttons">
        <ul>
        """
        for p in pages_list:
            if p == page:
                full_links += f'<li class="current"><div title="{self._weeks[p-1]} weeks ago">{p}</div></li>'
            else:
                full_links += f'<li><a href="{base}&page={p}" title="{self._weeks[p-1]} weeks ago">{p}</a></li>'
        full_links += """
        </ul>
    </div>
            """
        return full_links

    def links_by_char(self, base, page):
        full_links = """
    <div id="pagerbuttons">
        <ul>
        """
        for p in self._char_list:
            if p == page:
                full_links += f'<li class="current"><div>{p}</div></li>'
            else:
                full_links += f'<li><a href="{base}&page={p}">{p}</a></li>'
        full_links += """
        </ul>
    </div>
            """
        return full_links

    def counts(self, page):
        """
        Indexes are given starting from 1 
        """
        if self.byfirstchar:
            return ""
        return f"{self._start(page) + 1}-{self._end(page) + 1} of {self.lentgh}."

    def _start(self, page):
        if self.byweek:
            return self._w_start[page - 1]
        return (page-1)*self.page_size

    def _end(self, page):
        if self.byweek:
            return self._w_end[page - 1]
        return page * self.page_size if page < self.pages_max else self.lentgh

