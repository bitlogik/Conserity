#!/bin/ksh -e

echo "OpenBSD detected [experimental]"

conserity_log_file="log/outputBSD.log"

cmd_prt () {
  echo ""
  printf "%s  ....  " "$1"
}

ok () {
  msgout="DONE"
  [ ! -z "$1" ] && msgout="$1"
  printf "%s\n\n" $msgout
}

sep() {
  printf "%0.1s" "-"{1..60}
  echo ""
}

# Is root ?
if [[ `id -u` -ne 0 ]]; then
  echo "Conserity must be run as the root user."
  exit 1
fi

hostid=$(sysctl hw.uuid | sha256 | cut -c1-8)

IPHOST=$(ifconfig | grep broadcast | egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1)

# Users and Server Parameters

# ToDo check inputs

echo ""
echo 'Input the host web domain of this server (DNS A to the server IP) :'
read HOSTDOMAIN
if [[ $(host $HOSTDOMAIN | egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}') != $IPHOST ]]
then
  echo "Network tests show that this domain is not linked to this"
  echo "server IP ($IPHOST)."
  echo "Did you create a DNS A record for $HOSTDOMAIN pointing to"
  echo "the IP address of this server ?"
  echo "Did you input properly the domain name ?"
  exit 1
fi

echo "\nUser for Conserity (created if not exist): "
read fileUSER
echo "\nSSH port [22] : "
read SSHportc
if [ "$SSHportc" == '' ]
then
  SSHPORT="22"
else
  SSHPORT=$SSHportc
  echo "SSHd will listen to port $SSHPORT"
fi
echo "\nConserity encrypted partition size (MB) : "
read PDISKSZ
echo ""
echo "Conserity system option for the secret storage in the remote server(s) :"
echo "In one existing remote web server,"
echo "   configuration will be displayed."

# Initial update and clean up

cmd_prt "System packages update"
pkg_add -u > $conserity_log_file
ok

# Installation of packages

cmd_prt "Install packages needed"
pkg_add certbot nginx unzip-6.0p13 wget >> $conserity_log_file
ok

# Configure host for security

cmd_prt "Setup host for the security"

syspatch >> $conserity_log_file

# echo PasswordAuthentication no >> /etc/ssh/sshd_config
# [ -f "/etc/ssh/sshd_config.OLD" ] || mv /etc/ssh/sshd_config /etc/ssh/sshd_config.OLD
# SSHPORT=$SSHPORT fileUSER=$fileUSER envsubst < conf/sshd_config > /etc/ssh/sshd_config

rm -f /etc/ssh/ssh_host_*key*
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" < /dev/null >> $conserity_log_file
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" < /dev/null >> $conserity_log_file

# sysctl -p &>> $conserity_log_file || : 
/etc/rc.d/sshd restart >> $conserity_log_file

ok

# Configure web service
cmd_prt "Configuring the web server"
/etc/rc.d/nginx stop >> $conserity_log_file

echo ""
echo ""
echo " CERTBOT LetsEncrypt info and licence :"
certbot certonly --standalone --rsa-key-size 4096 --no-eff-email --must-staple --test-cert -d $HOSTDOMAIN

[ -f "/etc/nginx/nginx.conf.OLD" ] || mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.OLD
cp -f conf/nginx.conf /etc/nginx/
sed -i "s/DOMAIN/${HOSTDOMAIN}/g" /etc/nginx/nginx.conf
sed -i "s/pid /#pid /g" /etc/nginx/nginx.conf
sed -i "s/nginx;/www;/g" /etc/nginx/nginx.conf
sed -i "s/\/var\/log\/nginx\//\/var\/www\/logs\//g" /etc/nginx/nginx.conf
cp -f conf/dhparam.pem /etc/nginx/
/etc/rc.d/nginx start >> $conserity_log_file
sleep 2
echo QUIT | openssl s_client -connect $HOSTDOMAIN:443 -tls1_2 -status > /dev/null
ok

# Disable swap, so all in RAM
# ToDo
#cmd_prt "Disabling disk swap"
#swapctl -d
#ok

# Configure firewall
# ToDo with pf

# Add user
cmd_prt "Configuring the user"

if (id -u $fileUSER 1>/dev/null 2>&1)
then
  ok "SKIPPED"
else
  useradd -m $fileUSER
  ok
fi

webfile=`openssl rand -hex 16`
echo 'Web server domain where you will put the password: '
read WEBDOMAIN
PASSWORD=`openssl rand -base64 32`
WEBACCESS=`openssl rand -base64 16`

cmd_prt "Creating the encrypted partition"
echo "This can takes some time (5'000MB ~ 1min)"
dd if=/dev/zero of=/root/encryptdisk01 bs=1024 count=${PDISKSZ}k  >> $conserity_log_file
vnconfig vnd0 /root/encryptdisk01  >> $conserity_log_file
printf "a\n\n\n\nRAID\nw\nq\n" | disklabel -E vnd0  >> $conserity_log_file
TMPPWD=`mktemp /tmp/pwdvdXXXXXXXXXX`
chmod 0600 $TMPPWD
echo -e $PASSWORD > $TMPPWD
bioctl -c C -p $TMPPWD -l /dev/vnd0a softraid0  >> $conserity_log_file
rm -f $TMPPWD
sdrive=`dmesg | grep "^[sw]d[0-9a-f] at"| tail -1 | grep -o "^[sw]d[0-9a-f]"`
newfs -q ${sdrive}c  >> $conserity_log_file
cat <<EOF > $PWD/getpwd
#!/bin/ksh -e

a=\`wget --user UserConsY --password $WEBACCESS --no-cache --no-cookies -q -U 'ag3nt12340pw38' -O- https://${WEBDOMAIN}/prot-${hostid}/${webfile}\`
echo \$a
EOF

mkdir /home/$fileUSER/protected_files || :

cmd_prt "Setup the mount point and auto boot"
mount /dev/${sdrive}c /home/$fileUSER/protected_files/
chown $fileUSER /home/$fileUSER/protected_files
chgrp $fileUSER /home/$fileUSER/protected_files
chown -R $fileUSER /home/$fileUSER/protected_files/
chgrp -R $fileUSER /home/$fileUSER/protected_files/

cat <<EOF > /root/mountsp.sh
vnconfig vnd0 /root/encryptdisk01
$PWD/getpwd $fileIPclients | bioctl -s -c C -l /dev/vnd0a softraid0
mount /dev/${sdrive}c /home/$fileUSER/protected_files/
EOF

echo "@reboot  sleep 60 ; ksh /root/mountsp.sh ; sleep 15 ; /etc/rc.d/nginx restart && openssl s_client -connect $HOSTDOMAIN:443 -status" > /tmp/crontabroot
echo -e "00 4 * * 1  certbot certonly --standalone  --rsa-key-size 4096 --force-renewal -n --pre-hook \"/etc/rc.d/nginx stop\" --post-hook \"/etc/rc.d/nginx start\" --test-cert -d $HOSTDOMAIN" >> /tmp/crontabroot
crontab /tmp/crontabroot

ok

sep
echo -e "Conserity configured everything successfully ! "
echo -e "\n !!! Your SSH link will display a warning about the server"
echo -e "     keys change, just update the server public key"
echo -e "     in your SSH client."
echo "SSHd will listen to port $SSHPORT"

sep

echo ""
echo "Put in the the ${WEBDOMAIN} remote server :"
echo "-  <WebRoot>/prot-$hostid/$webfile file content (no line return) :"
echo $PASSWORD
echo ""
echo "and additionally in that remote \"prot-$hostid\" directory :"
echo "-  .htpasswd file content :"
echo "UserConsY:$(openssl passwd -apr1 -salt s4lto932 $WEBACCESS)"
echo ""
echo "-  .htaccess file content :"
echo "AuthUserFile /<PATH/TO/WebRoot>/prot-$hostid/.htpasswd"
echo "AuthGroupFile /dev/null"
echo "AuthName \"Private access\""
echo "AuthType Basic"
echo "<RequireAll>"
echo "  Require valid-user"
echo "  Require expr %{HTTP_USER_AGENT} == 'ag3nt12340pw38'"
echo "  Require ip $IPHOST"
echo "</RequireAll>"
echo ""
echo ""
sep


echo -e "\nYour web service socket has to listen to"
echo -e "localhost port 9090."

echo "A ${PDISKSZ} MB encrypted partition is mounted on"
echo "/home/${fileUSER}/protected_files/"
echo ""
echo "It will be automatically mounted at every boot,"
echo -e "reading the secret from the remote server(s).\n"


echo "Once you put the files in the ${WEBDOMAIN} remote web server,"

echo -e "you can reboot the machine to finish the installation."

sep
echo "REMEMBER THAT CONSERITY IS EXPERIMENTAL ON OPENBSD FOR NOW"
echo ""
