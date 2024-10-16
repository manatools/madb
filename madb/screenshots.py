from madb.helper import load_content_or_cache
import json

class Screenshots():
    def __init__(self):
        URL = "http://screenshots.debian.net/json/screenshots"
        content = load_content_or_cache(URL)
        try:
            self.scdb = json.loads(content)["screenshots"]
        except JSONDecodeError:
            self.scdb = None
            return
        self.keys = [x["name"] for x in self.scdb]

    def image_links(self, package):
        if self.scdb is None:
            return []
        if package in self.keys:
            links = [ {"small": x["small_image_url"], "large": x["large_image_url"]} for x in self.scdb if x["name"] == package  ]
            return links
