import yaml
import json
import os
from madb.helper import load_content_or_cache
import madb.config as config
from typing import List, Dict, Any, Optional

ADV_URL_BASE = "https://advisories.mageia.org/"


class Advisories:
    def __init__(self):
        # Read the list of advisories
        advisories_from_file = json.loads(
            load_content_or_cache(os.path.join(ADV_URL_BASE, "bugs.json"), long=False)
        )
        self.advisories_ids = [x["id"] for x in advisories_from_file]

        # Chemin du fichier global
        local_file = os.path.join(config.DATA_PATH, "cache", "advisories.json")

        # Read local file storing all advosories
        try:
            with open(local_file, "r") as f:
                self.advisories = json.load(f)
        except FileNotFoundError:
            self.advisories = []

        # etablish the list of not yet present advisories
        self.registerd_ids = [x["id"] for x in self.advisories]
        self.new_ids = list(set(self.advisories_ids) - set(self.registerd_ids))
        for fichier in self.new_ids:
            # Load and read missing advisory from local file
            donnees_individuelles = json.loads(
                load_content_or_cache(os.path.join(ADV_URL_BASE, fichier + ".json"))
            )
            self.advisories.append(donnees_individuelles)

        # write the local file if needed
        if len(self.new_ids) != 0:
            with open(local_file, "w") as f:
                json.dump(self.advisories, f)

    def adv_from_src_name(self, name: str, release: str, repo: str) -> List[str]:
        founds = []
        for adv in self.advisories:
            """Example
            {'schema_version': '1.6.2', 'id': 'MGAA-2021-0024', 'published': '2021-02-15T19:24:33Z', 'modified': '2021-02-15T18:40:29Z', 'summary': 'Updated gtk+3.0 packages adds support for disabling overlay scrollbars', 'details': 'This update adds an config option gtk-overlay-scrolling that allows the\nuser to opt out of overlay scrollbars since they sometimes end up hiding\ntext or does not show up at all by setting the environment variable\nGTK_OVERLAY_SCROLLING=0\n', 'references': [{'type': 'ADVISORY', 'url': 'https://advisories.mageia.org/MGAA-2021-0024.html'}, {'type': 'REPORT', 'url': 'https://bugs.mageia.org/show_bug.cgi?id=28357'}, {'type': 'REPORT', 'url': 'https://bugs.mageia.org/show_bug.cgi?id=28248'}], 'affected': [{'package': {'ecosystem': 'Mageia:7', 'name': 'gtk+3.0', 'purl': 'pkg:rpm/mageia/gtk+3.0?distro=mageia-7'}, 'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}, {'fixed': 'gtk+3.0-3.24.8-1.1.mga7'}]}], 'ecosystem_specific': {'section': 'core'}}], 'credits': [{'name': 'Mageia', 'type': 'COORDINATOR', 'contact': ['https://wiki.mageia.org/en/Packages_Security_Team']}]}
            """
            if "affected" in adv.keys():
                for pkg in adv["affected"]:
                    rel = pkg["package"]["ecosystem"][7:]
                    if rel == release:
                        section = pkg["ecosystem_specific"]["section"]
                        if section == repo:
                            if name == pkg["package"]["name"]:
                                founds.append(adv["id"])
                            else:
                                for range in pkg["ranges"]:
                                    for event in range["events"]:
                                        if "fixed" in event.keys() and section == repo:
                                            if (
                                                f'{pkg["package"]["name"]}-{event["fixed"]}'
                                                in name
                                            ):
                                                founds.append(adv["id"])
        return founds
