#!/data/data/com.termux/files/usr/bin/bash
echo -e "\e[1;31mInstall Metasploit-Framework v 4.17.1\e[0m"
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
echo "Mendownload Modul-Modul Yg Dibutuhkan"

apt install -y autoconf bison clang coreutils axel curl findutils git apr apr-util libffi-dev libgmp-dev libpcap-dev postgresql-dev readline-dev libsqlite-dev openssl-dev libtool libxml2-dev libxslt-dev ncurses-dev pkg-config wget make ruby-dev libgrpc-dev termux-tools ncurses-utils ncurses unzip zip tar postgresql termux-elf-cleaner

#Update & Upgrade System
apt update && apt upgrade

#Mendownload Framework dan Mengektraknya
echo "Mendownload File Metasploit"
cd $HOME
curl -L https://github.com/rapid7/metasploit-framework/archive/4.17.2.tar.gz | tar xz
mv metasploit-framework-4.17.2 metasploit-framework
cd $HOME/metasploit-framework
sed '/rbnacl/d' -i Gemfile.lock
sed '/rbnacl/d' -i metasploit-framework.gemspec
gem install bundler
sed 's|nokogiri (1.*)|nokogiri (1.8.0)|g' -i Gemfile.lock

#menlinkkan libxml2
ln -sf $PREFIX/include/libxml2/libxml $PREFIX/include/

#Install Nokogiri
gem install nokogiri -v 1.8.0 -- --use-system-libraries

#Install Metasploit
cd $HOME/metasploit-framework
bundle install -j5

#Fix Shebangs
$PREFIX/bin/find -type f -executable -exec termux-fix-shebang \{\} \;

#Membuang Modul Auxiliary http pdf authors
rm ./modules/auxiliary/gather/http_pdf_authors.rb

#Fixing error linker
termux-elf-cleaner /data/data/com.termux/files/usr/lib/ruby/gems/2.4.0/gems/pg-0.20.0/lib/pg_ext.so

#Membuat Database
echo "Creating database"
cd $HOME/metasploit-framework/config
curl -LO https://raw.githubusercontent.com/psycosocial/shell/master/database.yml
mkdir -p $PREFIX/var/lib/postgresql
initdb $PREFIX/var/lib/postgresql
pg_ctl -D $PREFIX/var/lib/postgresql start
createuser msf
createdb msf_database
cd $HOME

#Membuat link metasploit command
ln -sf /data/data/com.termux/files/home/metasploit-framework/msfconsole /data/data/com.termux/files/usr/bin/
ln -sf /data/data/com.termux/files/home/metasploit-framework/msfvenom /data/data/com.termux/files/usr/bin/
ln -sf /data/data/com.termux/files/home/metasploit-framework/msfupdate /data/data/com.termux/files/usr/bin/

#Installasi Sukses
rm msfinstall.sh
echo "#################################"
echo -e "        \e[1;32mBy : Idra Cakepz\e[0m"
echo "#################################"
echo -e"\e[1;32mJalankan Metasploit dg command ( msfconsole)\e[0m"
