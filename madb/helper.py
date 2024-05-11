import re
import madb.config as config
import yaml
import requests
import hashlib
import os
import time
from itertools import chain

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
CACHE_TTL = 60 * 60 * 24  # Cache expiration time: 1 day
CACHE_SIZE = 5
os.makedirs(CACHE_DIR, exist_ok=True)

#  absolute path of cached file for specified URL
def _get_cache_filepath(url):
    filename = hashlib.sha256(url.encode("utf-8")).hexdigest()[:10]
    filepath = os.path.join(CACHE_DIR, filename)
    return filepath

# Load cache content or from URL after expiration
def load_content_or_cache(url):
    filepath = _get_cache_filepath(url)
    if not os.path.exists(filepath) or time.time() - os.path.getctime(filepath) > CACHE_TTL:
        response = requests.get(url)
        with open(filepath, "w") as f:
            f.write(response.content.decode())
            print(f"Cache {filepath} wrotten")
    with open(filepath, "r") as f:
        content = f.read()
    return content

# Clean the cache every day
def clean_cache():
    time.sleep(10)
    while True:
        for cached_file in os.listdir(CACHE_DIR):
            if time.time() - os.path.getctime(os.path.join(CACHE_DIR, cached_file)) > CACHE_TTL:
                os.remove(cached_file)
        time.sleep(3600 * 24)


class BugReport():
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

    def __init__(self):
        self.data = {}

    def from_number(self, number):
        self.number = number
        self.url = os.path.join(config.BUGZILLA_URL, "rest/bug", self.number)

        headers = {'Accept': 'application/json'}
        r = requests.get(self.url, params = [("include_fields", self.column)], headers=headers)
        if r.status_code == 200 and r.json()["faults"] == []:
            releases = []
            entry =  r.json()['bugs'][0]
            results = []
            for srpm in  re.split(';|,| ',entry['cf_rpmpkg']):
                pkg = srpm.strip()
                if pkg == "":
                    continue
                analyze = re.search(r"([\w\-\+_]+)-\d", pkg)
                if analyze is not None:
                    pkg = analyze.group(1)
                results += [pkg]
            self.data["srpms"] = results
            if entry["version"] not in releases:
                releases.append(entry["version"].lower())
            if "status_whiteboard" in entry.keys():
                wb = re.findall(r"\bMGA(\d+)TOO", entry["status_whiteboard"])
                for key in wb:
                    if key not in releases:
                        releases.append(key)
            self.data["releases"] = releases

    def get_srpms(self):
        return self.data["srpms"]

    def get_releases(self):
        return self.data["releases"]

class Pagination():
    def __init__(self, data, page_size=0, pages_number=0, byweek=False):
        """
        Pages number is starting from 1
        Only one of page_size, pages_number or byweek has to be set
        If byweek is True, data are truncated in pages by week of build time, from more recent to older
        rpm index in data starts from 0
        """
        self.data = data
        self.byweek = byweek
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

            self._w_end.append(i - 1)
            older = min([rpm.get_build_time() for rpm in data])
            self.pages_max = len(self._w_start)

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

    def counts(self, page):
        """
        Indexes are given starting from 1 
        """
        return f"{self._start(page) + 1}-{self._end(page) + 1} of {self.lentgh}."

    def _start(self, page):
        if self.byweek:
            return self._w_start[page - 1]
        return (page-1)*self.page_size

    def _end(self, page):
        if self.byweek:
            return self._w_end[page - 1]
        return page * self.page_size if page < self.pages_max else self.lentgh

