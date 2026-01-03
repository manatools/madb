FROM docker.io/mageia:9
label MAINTAINER="Mageia Community"

RUN sed -i "s/^mirrorlist/#mirrorlist/" /etc/yum.repos.d/*
RUN sed -i 's|#baseurl=https://mirrors.kernel.org/mageia|baseurl=https://mirror.serverion.com/mageia|' /etc/yum.repos.d/*
RUN dnf upgrade  -y --refresh
RUN dnf install  --setopt=install_weak_deps=False -y 'dnf-command(config-manager)'
RUN dnf config-manager --add-repo 'https://repository.mageialinux-online.org/9/x86_64/media/core/mlo9-x86_64-core.repo'
RUN dnf copr enable -y papoteur/dnf5-mga
RUN dnf install  -y  --setopt=install_weak_deps=False madb rpmlint-mageia-policy
RUN dnf copr disable -y papoteur/dnf5-mga
RUN rm -f /etc/yum.repos.d/mlo9-x86_64-core.repo /etc/yum.repos.d/_copr:copr.fedorainfracloud.org:papoteur:dnf5-mga.repo

RUN sed -e "s|var/www/html|var/lib|" /var/lib/madb/madb/config.py.in >/var/lib/madb/madb/config.py

RUN python3 /var/lib/madb/makecache.py
RUN python3 /var/lib/madb/makeadvisories.py

# Define init command
WORKDIR "/var/lib/madb"
CMD ["/usr/bin/bash", "/usr/bin/start_madb.sh"]
 
# Expose ports
EXPOSE 5003
