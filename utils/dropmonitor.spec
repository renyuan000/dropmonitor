Name: %{?name}
#Name: tcpspeed
Version: %{?Ver}
#Release:	1%{?dist}
Release:	%{?rel}%{?dist}
Summary: %{?name} test version	

Group: System Environment/Kernel
License: GPL	
#URL:		
Source0: dummy	
BuildRoot:	%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
#BuildRequires:	
#Requires:	

%description
 %{?name} kernel module

%prep
#%setup -q
%setup -D -T


%build
make


%install
#make install DESTDIR=%{buildroot}
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/local/%{name}/module
install -m 644 %{name}.ko %{buildroot}/usr/local/%{name}/module/

#mkdir -p %{buildroot}/usr/local/%{name}/conf
#install -m 644 %{name}.conf %{buildroot}/usr/local/%{name}/conf/

mkdir -p %{buildroot}/usr/local/%{name}/bin
install -m 755 %{name}.sh %{buildroot}/usr/local/%{name}/bin/

mkdir -p %{buildroot}/usr/bin/
install -m 755 %{name}.sh %{buildroot}/usr/bin/
#mkdir -p %{buildroot}/etc/init.d/
#install -m 755 %{name} %{buildroot}/etc/init.d/

#%post
#cp /usr/local/%{name}/bin/%{name} /etc/init.d/
#chkconfig --add %{name}
#chkconfig --level 345 %{name} on

#%preun
#chkconfig --level 345 %{name} off
#chkconfig --del %{name}
#rm -rf /etc/init.d/%{name}

%clean
rm -rf %{buildroot}


%files
/usr

%defattr(-,root,root,-)
%doc



%changelog
* Thu Jan 8 2015 17:32:06 Renyuan <ren-yuan@dnion.com>
- initial version

