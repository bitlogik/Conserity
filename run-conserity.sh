#!/bin/bash -e

# Conserity : Strengthen you server and protect your data
# Copyright (C) 2019-2020  BitLogiK
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

test_file () {
  # test_file FileName SHA256sum
  printf "\nTesting $1 ..."
  if ! ( echo "$2 $1" | sha256sum --status -c - ) then
    echo -e "\nERROR : File $1 is not present or corrupted"
    exit 1
  fi
  printf "  file OK\n\n"
}

# ToDo : COLS=$(tput cols), tput cup $COL $ROW

sep
printf "%35s" "Conserity setting up"
echo ""
sep

# Test the host system

cmd_prt "Detecting host Linux system"

# To Do : system detection and adapt script
if ! (cat /etc/os-release | grep -E "10 \(buster\)|18\.04(\.[0-9]+)? LTS \(Bionic Beaver\)|19\.04 \(Disco Dingo\)|19\.10 \(Eoan Ermine\)|20\.04(\.[0-9]+)? LTS \(Focal Fossa\)" > /dev/null ) then
  echo "Conserity only runs on Debian 10, Ubuntu 18.04, 19.04, 19.10 or 20.04."
  exit 1
fi
ok

# Is root ?
if [[ $EUID -ne 0 ]]; then
  echo "Conserity must be run as the root user."
  exit 1
fi

if [ -x "$(which curl)" ]; then
  IPHOST=$(curl -s https://api.ipify.org/)
elif [ -x "$(which wget)" ]; then
  IPHOST=$(wget -qO- https://api.ipify.org/)
else
  echo "Please install wget."
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# Users and Server Parameters

# ToDo check inputs


if !(command -v host > /dev/null) then
  cmd_prt "'host' command not present, installing it"
  apt-get -y update > $conserity_log_file
  apt-get -y install bind9-host >> $conserity_log_file
  ok
fi
echo ""
echo 'Input the host web domain of this server (DNS A to the server IP) :'
read -p '> ' HOSTDOMAIN
if [[ $(host $HOSTDOMAIN | egrep -o '([0-9]{1,3}\.){3}[0-9]{1,3}') != $IPHOST ]]
 
then
  echo "Network tests show that this domain is not linked to this"
  echo "server IP ($IPHOST)."
  echo "Did you create a DNS A record for $HOSTDOMAIN pointing to"
  echo "the IP address of this server ?"
  echo "Did you input properly the domain name ?"
  exit 1
fi

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

# web, php, uwsgi
WebServiceType=web


# Initial update and clean up

echo ""
cmd_prt "System packages update"
apt-get -y update >> $conserity_log_file
apt-get -y upgrade >> $conserity_log_file
ok

# Installation of packages

cmd_prt "Install packages needed"
echo ""
apt-get -y -qq install openssh-server certbot nginx-light ufw unzip wget >> $conserity_log_file
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
cmd_prt "Configuring the web server"
service nginx stop >> $conserity_log_file
ufw disable >> $conserity_log_file

if !(id -u nginx &> /dev/null) then
  adduser --system --no-create-home --shell /bin/false --group --disabled-login nginx
fi

echo ""
echo ""
echo " CERTBOT LetsEncrypt info and licence :"
certbot certonly --standalone --rsa-key-size 4096 --no-eff-email --server 'https://api.buypass.com/acme/directory' -d $HOSTDOMAIN

[ -f "/etc/nginx/nginx.conf.OLD" ] || mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.OLD
cp -f conf/nginx.conf /etc/nginx/
sed -i "s/DOMAIN/${HOSTDOMAIN}/g" /etc/nginx/nginx.conf
cp -f conf/dhparam.pem /etc/nginx/
service nginx start >> $conserity_log_file
sleep 2
echo QUIT | openssl s_client -connect $HOSTDOMAIN:443 -tls1_2 -status > /dev/null
ok


# Configure firewall

cmd_prt "Configuring firewall"
ufw -f reset  >> $conserity_log_file
ufw default deny incoming >> $conserity_log_file
ufw default allow outgoing >> $conserity_log_file
ufw allow $SSHPORT/tcp >> $conserity_log_file
ufw limit $SSHPORT/tcp >> $conserity_log_file
ufw allow 443/tcp >> $conserity_log_file
ufw allow 80/tcp >> $conserity_log_file
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
  chmod u=rw,go=  /home/$fileUSER/.ssh/*
  systemctl reload sshd
  ok
else
  ok "SKIPPED"
fi

hostid=$(cat /etc/machine-id | sha256sum | cut -c1-8)


echo -e "00 4 * * 1  certbot certonly --standalone  --rsa-key-size 4096 --force-renewal -n --pre-hook \"service nginx stop\" --post-hook \"service nginx start\" --server 'https://api.buypass.com/acme/directory' -d $HOSTDOMAIN" >> /var/spool/cron/crontabs/root
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


echo -e "\nYour web service socket has to listen to"
echo -e "localhost port 9090."

echo -e "This can be changed by editing /etc/nginx/nginx.conf"

sep
echo -e "you can reboot the machine to finish the installation."

sep
echo ""
