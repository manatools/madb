FROM docker.io/mageia:9
label MAINTAINER="Mageia Community"

ENV MIRROR="https://mirror.serverion.com/mageia/distrib/9/x86_64/media/core"
ENV FORCE_MIRROR="--repofrompath=forcemirrorcorerel,${MIRROR}/release/ --repofrompath=forcemirrorcoreupd,${MIRROR}/updates/ --disablerepo=* --enablerepo=forcemirrorcorerel --enablerepo=forcemirrorcoreupd"

RUN dnf upgrade ${FORCE_MIRROR} -y --refresh
RUN dnf install ${FORCE_MIRROR} --setopt=install_weak_deps=False -y 'dnf-command(config-manager)'
RUN dnf config-manager --add-repo 'https://repository.mageialinux-online.org/9/x86_64/media/core/mlo9-x86_64-core.repo'
RUN dnf copr enable -y papoteur/dnf5-mga
RUN dnf install -y madb rpmlint-mageia-policy
RUN dnf copr disable -y papoteur/dnf5-mga
RUN rm -f /etc/yum.repos.d/mlo9-x86_64-core.repo /etc/yum.repos.d/_copr:copr.fedorainfracloud.org:papoteur:dnf5-mga.repo


RUN sed -e "s|var/www/html|var/lib|" /var/lib/madb/madb/config.py.in >/var/lib/madb/madb/config.py
RUN /usr/bin/makeadvisories.py

# Define init command
WORKDIR "/var/lib/madb"
CMD ["/usr/bin/bash", "/usr/bin/start_madb.sh"]
 
# Expose ports
EXPOSE 5003 
