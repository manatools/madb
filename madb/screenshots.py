from madb.helper import load_content_or_cache
import json

class Screenshots():
    def __init__(self):
        URL = "http://screenshots.debian.net/json/screenshots"
        content = load_content_or_cache(URL)
        self.scdb = json.loads(content)["screenshots"]
        self.keys = [x["name"] for x in self.scdb]

    def image_links(self, package):
        if package in self.keys:
            links = [ {"small": x["small_image_url"], "large": x["large_image_url"]} for x in self.scdb if x["name"] == package  ]
            return links