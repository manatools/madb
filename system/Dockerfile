FROM docker.io/mageia:9
label MAINTAINER="Mageia Community"
 
RUN dnf upgrade -y --refresh
RUN dnf install -y 'dnf-command(config-manager)'
RUN dnf config-manager --add-repo 'https://repository.mageialinux-online.org/9/x86_64/media/core/mlo9-x86_64-core.repo'
RUN dnf copr enable -y papoteur/dnf5-mga
RUN dnf install -y madb rpmlint-mageia-policy python3-schedule
RUN dnf copr disable -y papoteur/dnf5-mga
RUN rm -f  /etc/yum.repos.d/mlo9-x86_64-core.repo   /etc/yum.repos.d/_copr:copr.fedorainfracloud.org:papoteur:dnf5-mga.repo

RUN sed -e "s|var/www/html|var/lib|" /var/lib/madb/madb/config.py.in >/var/lib/madb/madb/config.py
RUN sed -ie "s|= DATA_PATH|= '/var/log/madb'|" /var/lib/madb/madb/config.py

# Define init command
WORKDIR "/var/lib/madb"
CMD ["/usr/bin/gunicorn","--workers=8", "--timeout=90",  "wsgi:madb_app", "--log-level=INFO","--bind=:5003"]
 
# Expose ports
EXPOSE 5003
