import re
import config
def groups():
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