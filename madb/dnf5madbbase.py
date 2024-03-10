import libdnf5
import os
from datetime import datetime, timedelta
from libdnf5.common import QueryCmp_GLOB as GLOB
import madb.config as config


class Dnf5MadbBase(libdnf5.base.Base):

    def __init__(self, release, arch, root):

        self.release = release
        self.arch = arch
        self.root = root

        libdnf5.base.Base.__init__(self)
        # Create a new Base object
        self._base = libdnf5.base.Base()
        self._base_config = self._base.get_config()
        self._base_config.installroot = root
        self._base.setup()
        self._base.config_file_path = os.path.join(root, "dnf/dnf.conf.example")
        self._base.load_config()
        vars = self._base.get_vars().get()
        vars.set('releasever', release)
        # vars.set('basearch', arch)
        vars.set('distarch', arch)
        self._base_config.cachedir = os.path.join(root, "dnf", "cache")
        self._base_config.reposdir = os.path.join(root, "dnf", "etc","distro.repos.d")
        self._base_config.logdir = "cache"
        self._base_config.keepcache = True
        self._base_config.module_platform_id = f"Mageia:{release}"
        # self._base_config.metadata_expire = 20
        self._repo_sack = self._base.get_repo_sack()
        repos = {}
        for section in ("core", "nonfree", "tainted"):
            for cl in ("backports", "backports_testing", "release", "updates", "updates_testing"):
                repo_name = f"{release}-{arch}-{section}-{cl}"
                repos[repo_name] = self._repo_sack.create_repo(repo_name)
                repos[repo_name].get_config().baseurl = os.path.join(config.MIRROR_URL, release, arch, "media", section, cl)
        self._repo_sack.update_and_load_enabled_repos(False)


    def search_name(self, values, showdups=False):
        """Search in a list of package attributes for a list of keys.

        :param values: the values to match
        :param showdups: show duplicate packages or latest (default)
        :return: a list of package objects
        """
        if not showdups:
            query = libdnf5.rpm.PackageQuery(self._base)
            query.filter_arch([self.arch])
            query.filter_name(values, GLOB)
        return query

    def search_updates(self, backports=False):
        query = libdnf5.rpm.PackageQuery(self._base)
        query.filter_arch([self.arch])
        if backports:
            query.filter_repo_id(["*backports*"], GLOB)
        else:
            query.filter_repo_id(["*updates*"], GLOB)
        query.filter_recent(int((datetime.now() - timedelta(days=7)).timestamp()))
        return query

    def provides_requires(self, rpm_list):
        query = libdnf5.rpm.PackageQuery(self._base)
        query.filter_provides(rpm_list)
        return query


    def repo_enabled(self):
        query = libdnf5.repo.RepoQuery(self._base)
        query.filter_enabled(True)
        return query