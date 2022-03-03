#!/bin/bash -e

# Conserity : Strengthen you server and protect your data
# Copyright (C) 2019-2022  BitLogiK
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

# Conserity script
# For Debian and Ubuntu

# #### Conserity Parameters ####

conserity_log_file="log/output.log"

# #### CONSERITY SCRIPT

# Display functions

cmd_prt () {
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


# ToDo : COLS=$(tput cols), tput cup $COL $ROW

sep
printf "%35s" "Conserity setting up"
echo ""
sep

# Test the host system

cmd_prt "Detecting host Linux system"

# To Do : system detection and adapt script
if ! (cat /etc/os-release | grep -E "10 \(buster\)|11 \(bullseye\)|18\.04(\.[0-9]+)? LTS \(Bionic Beaver\)|19\.04 \(Disco Dingo\)|19\.10 \(Eoan Ermine\)|20\.04(\.[0-9]+)? LTS \(Focal Fossa\)" > /dev/null ) then
  echo "Conserity only runs on Debian 10, Ubuntu 18.04, 19.04, 19.10 or 20.04."
  exit 1
fi
ok

if (cat /etc/os-release | grep -E "18\.04\..+ LTS \(Bionic Beaver\)" > /dev/null) then
  echo "On Ubuntu 18.04, LUKS is an older version."
  echo "The security of the disk encryption is lower than LUKS2"
  read -p ' Continue anyway ? [y/N] : ' U18choice
  if [[ $U18choice != "y" ]]; then
    exit 1
  fi
fi

# Is root ?
if [[ $EUID -ne 0 ]]; then
  echo "Conserity must be run as the root user."
  exit 1
fi


export DEBIAN_FRONTEND=noninteractive

# Users and Server Parameters

echo ""
read -p 'User for Conserity (created if not exist): ' fileUSER
echo ""
read -p 'SSH port [22] : ' SSHportc
if [ "$SSHportc" == '' ]
then
  SSHPORT="22"
else
  SSHPORT=$SSHportc
echo "SSHd will listen to port $SSHPORT"
fi
echo ""
read -p 'Conserity encrypted partition size (MB) : ' PDISKSZ
echo ""
echo "Conserity system option for the secret storage in the remote server(s) :"
echo "In one existing remote web server,"
echo "configuration will be displayed."


# Initial update and clean up

echo ""
cmd_prt "System packages update"
apt-get -y update >> $conserity_log_file
apt-get -y upgrade >> $conserity_log_file
ok

# Installation of packages

cmd_prt "Install packages needed"
echo ""
apt-get -y -qq install openssh-server ufw cryptsetup wget >> $conserity_log_file
ok


# Configure host for security

cmd_prt "Generating new SSH keys"
rm -f /etc/ssh/ssh_host_*key* >> $conserity_log_file
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" < /dev/null >> $conserity_log_file
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" < /dev/null >> $conserity_log_file
ok

cmd_prt "Setup host for the security"

[ -f "/etc/sysctl.conf.OLD" ] || mv /etc/sysctl.conf /etc/sysctl.conf.OLD
cp conf/sysctl.conf /etc/sysctl.conf

[ -f "/etc/ssh/sshd_config.OLD" ] || mv /etc/ssh/sshd_config /etc/ssh/sshd_config.OLD
SSHPORT=$SSHPORT fileUSER=$fileUSER envsubst < conf/sshd_config > /etc/ssh/sshd_config

sysctl -p &>> $conserity_log_file || : 
service sshd restart >> $conserity_log_file
ok

# Configure web service
ufw disable >> $conserity_log_file

# Disable swap, so all in RAM
cmd_prt "Disabling disk swap"
swapoff -a >> $conserity_log_file
ok

# Configure firewall

cmd_prt "Configuring firewall"
ufw -f reset  >> $conserity_log_file
ufw default deny incoming >> $conserity_log_file
ufw default allow outgoing >> $conserity_log_file
ufw allow $SSHPORT/tcp >> $conserity_log_file
ufw limit $SSHPORT/tcp >> $conserity_log_file
# ufw allow 443/tcp >> $conserity_log_file
# ufw allow 80/tcp >> $conserity_log_file
ufw deny 68 >> $conserity_log_file
ufw deny 5100 >> $conserity_log_file
ufw allow 53 >> $conserity_log_file
ufw -f enable >> $conserity_log_file
ok


# Add user
cmd_prt "Configuring the user"
if !(id -u $fileUSER &> /dev/null) then
  echo ""
  echo ""
  adduser --disabled-password --gecos "" $fileUSER
  mkdir -p /home/$fileUSER/.ssh
  if [ -f ~/.ssh/authorized_keys ]; then
    cp ~/.ssh/authorized_keys /home/$fileUSER/.ssh/authorized_keys
  fi
  chown -R $fileUSER /home/$fileUSER/.ssh
  chgrp $fileUSER /home/$fileUSER/.ssh
  chown -R :$fileUSER /home/$fileUSER/.ssh
  chmod u=rwx,go=  /home/$fileUSER/.ssh
  if [ -n "$(ls -A /home/$fileUSER/.ssh)" ]; then
    chmod u=rw,go=  /home/$fileUSER/.ssh/*
  fi
  systemctl reload sshd
  ok
else
  ok "SKIPPED"
fi

hostid=$(cat /etc/machine-id | sha256sum | cut -c1-8)


webfile=`openssl rand -hex 16`
read  -p 'Web server domain where you will put the password: ' WEBDOMAIN
PASSWORD=`openssl rand -base64 32`
WEBACCESS=`openssl rand -base64 16`
fallocate -l ${PDISKSZ}M /root/encryptdisk01
echo ""
cmd_prt "Creating the encrypted partition"
echo "This can takes some time (5'000MB ~ 1min)"
shred /root/encryptdisk01
echo $PASSWORD | cryptsetup -q luksFormat /root/encryptdisk01 --pbkdf-memory 1024
echo $PASSWORD | cryptsetup luksOpen /root/encryptdisk01 volume1
cat <<EOF > $PWD/getpwd
#!/bin/sh -e

a=\`wget --user UserConsY --password $WEBACCESS --no-cache --no-cookies -q -U 'ag3nt12340pw38' -O- https://${WEBDOMAIN}/prot-${hostid}/${webfile}\`
echo \$a
EOF


mkfs.ext4 -j /dev/mapper/volume1 &>> $conserity_log_file
mkdir /home/$fileUSER/protected_files
ok

cmd_prt "Setup the mount point and auto boot"
mount /dev/mapper/volume1 /home/$fileUSER/protected_files
chown $fileUSER /home/$fileUSER/protected_files
chgrp $fileUSER /home/$fileUSER/protected_files
chown -R $fileUSER /home/$fileUSER/protected_files/*
chgrp -R $fileUSER /home/$fileUSER/protected_files/*

cat <<EOF > /root/mountsp.sh
$PWD/getpwd | $(type -P cryptsetup) luksOpen /root/encryptdisk01 volume1
mount /dev/mapper/volume1 /home/$fileUSER/protected_files
EOF

chmod +x $PWD/getpwd

echo "@reboot  sleep 60 ; bash /root/mountsp.sh ; sleep 15 ; /usr/sbin/service nginx reload && openssl s_client -connect $HOSTDOMAIN:443 -status" > /var/spool/cron/crontabs/root
crontab /var/spool/cron/crontabs/root

ok


sep
echo -e "Conserity configured everything successfully ! "
echo -e "\n !!! Your SSH link will display a warning about the server"
echo -e "     keys change, just update the server public key"
echo -e "     in your SSH client."
echo "SSHd will listen to port $SSHPORT"
echo ""
echo " --- New SSH keys fingerprint :"
echo "RSA4096 (old PuTTY format)"
ssh-keygen -l -E md5 -f /etc/ssh/ssh_host_rsa_key
echo "RSA4096 (new format)"
ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key
echo "Ed25519 (old PuTTY format)"
ssh-keygen -l -E md5 -f /etc/ssh/ssh_host_ed25519_key
echo "Ed25519 (new format)"
ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key
echo ""

sep

echo ""
echo "Put in the the ${WEBDOMAIN} remote server :"
echo "-  <WebRoot>/prot-$hostid/$webfile file content (no line return) :"
echo $PASSWORD
echo ""
echo "and additionally in that remote \"prot-$hostid\" directory :"
echo "-  .htpasswd file content :"
echo "UserConsY:$(openssl passwd -apr1 --salt s4lto932 $WEBACCESS)"
echo ""
echo "-  .htaccess file content :"
echo "AuthUserFile /<PATH/TO/WebRoot>/prot-$hostid/.htpasswd"
echo "AuthGroupFile /dev/null"
echo "AuthName \"Private access\""
echo "AuthType Basic"
echo "<RequireAll>"
echo "  Require valid-user"
echo "  Require expr %{HTTP_USER_AGENT} == 'ag3nt12340pw38'"
echo "  Require ip <<IP of this server>>"
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

echo "Once you put the files in the ${WEBDOMAIN} remote web server"
echo "and tested here with ./getpwd,"
echo -e "you can reboot the machine to finish the installation."

sep
echo ""
