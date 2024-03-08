TOP_RELEASE = 9
APP_NAME = "Mageia App DB"
DATA_PATH = "/home/yves/dev/madb2"
DEF_GROUPS_FILE = "/usr/share/rpmlint/config.d/distribution.exceptions.conf"
ARCHES = {
    "x86_64": "x86 64bits",
    "x86_32": "x86 32bits",
    "arm_64": "Arm 64bits",
    "arm_32": "Arm 32bits v7hl",
}
DISTRIBUTION = {
    "cauldron": "Mageia cauldron",
    str(TOP_RELEASE): "Mageia " + str(TOP_RELEASE),
    str(TOP_RELEASE - 1): "Mageia " + str(TOP_RELEASE -1),
}