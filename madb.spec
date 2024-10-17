Name:           madb
Group:          Networking/Other
Version:        0.1
Release:        %mkrel 1
Summary:        Publication of rpm packages on an Internet site
License:        AGPL
Source0:        %{name}-%{version}.tar.xz

BuildArch:      noarch
URL:            https://github.com/manatools/madb

BuildRequires:  python3-devel

Requires:       python3-gunicorn
Requires:       python3-pyvis
Requires:       python3-libdnf5
Requires:       python3-flask
Requires:       python3-beautifulsoup4
Requires:       python3-humanize
Requires:       python3-pandas

Requires:       nginx

%description
The application publish data from RPM packages database.
It is accesible by web browser on port 5003.

%prep
%autosetup -p1

%build

%install
mkdir -p %{buildroot}%{_sharedstatedir}/madb/cache
mkdir -p %{buildroot}%{_sharedstatedir}/madb/dnf
# used by pyvis 
mkdir -p %{buildroot}%{_sharedstatedir}/madb/lib

mkdir -p %{buildroot}%{_sharedstatedir}/madb/madb
mkdir -p %{buildroot}%{_sharedstatedir}/madb/static
mkdir -p %{buildroot}%{_unitdir}
mkdir -p %{buildroot}%{_sysconfdir}/nginx/conf.d
install -Dm 644  madb/*.py      %{buildroot}%{_sharedstatedir}/madb/madb/
install -Dm 644  madb/config.py.in   %{buildroot}%{_sharedstatedir}/madb/madb/
install -Dm 644  wsgi.py        %{buildroot}%{_sharedstatedir}/madb/
cp -R  madb/templates           %{buildroot}%{_sharedstatedir}/madb/madb/
cp -R  madb/static              %{buildroot}%{_sharedstatedir}/madb/madb/
install -Dm 644  system/madb.conf %{buildroot}%{_sysconfdir}/nginx/conf.d/
install -Dm 644  system/madb-cache.service %{buildroot}%{_unitdir}/
install -Dm 644  system/madb-cache.timer %{buildroot}%{_unitdir}/
install -Dm 644  system/madb.service %{buildroot}%{_unitdir}/
install -Dm 644  system/gunicorn-madb.service %{buildroot}%{_unitdir}/
install -Dm 644  system/gunicorn-madb.socket %{buildroot}%{_unitdir}/

%files
%license LICENSE
%{_sharedstatedir}/madb/madb
%{_sharedstatedir}/madb/wsgi.py
%attr(0644,%{name},%{name}) %{_sharedstatedir}/madb/dnf
%attr(0644,%{name},%{name}) %{_sharedstatedir}/madb/cache
%attr(0644,%{name},%{name}) %{_sharedstatedir}/madb/lib
%{_sysconfdir}/nginx/conf.d/madb.conf
%{_unitdir}/madb-cache.service
%{_unitdir}/madb-cache.timer
%{_unitdir}/madb.service
%{_unitdir}/gunicorn-madb.service
%{_unitdir}/gunicorn-madb.socket

%pre
%_pre_useradd %{name} /dev/null /bin/false
%create_ghostfile %{_sharedstatedir}/madb/madb.log %{name} %{name} 0640
%create_ghostfile %{_sharedstatedir}/madb/dnf/logs/dnf5.log %{name} %{name} 0640
/bin/systemctl restart nginx.service || :

%post
%_post_service %{name}.service %{name}-cache.service gunicorn-madb.service gunicorn-madb.socket
 
%preun
%_preun_service %{name}.service %{name}-cache.service gunicorn-madb.service gunicorn-madb.socket

%postun
%_postun_userdel %{name}
