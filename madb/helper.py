import re
import madb.config as config
import yaml
import requests
import hashlib
import os
import time

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