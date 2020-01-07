#!/bin/bash -e

# Conserity : Strengthen you server and protect your data
# Copyright (C) 2019  BitLogiK
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
# For Debian 10

# To Do
# * Secure the tools installation hash of the dl code and scripts

# #### Conserity Parameters ####

conserity_log_file="log/output.log"
DockerMachinev=v0.16.0

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
if ! (cat /etc/os-release | grep "10 (buster)" > /dev/null ) then
  echo "For now, Conserity only runs on Debian 10."
  exit 1
fi
ok

# Is root ?
if [[ $EUID -ne 0 ]]; then
  echo "Conserity must be run as the root user."
  exit 1
fi

IPHOST=$(ip route get 1 | sed -n 's/^.*src \([0-9.]*\) .*$/\1/p')

export DEBIAN_FRONTEND=noninteractive

cmd_prt "Quick install for DNS check"
echo ""
apt-get -y update > $conserity_log_file
apt-get -y install dnsutils >> $conserity_log_file
ok

# Users and Server Parameters

# ToDo check inputs

echo ""
echo 'Input the host web domain of this server (DNS A to the server IP) :'
read HOSTDOMAIN
if [[ $(dig +short $HOSTDOMAIN) != $IPHOST ]]
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
read -p 'Conserity encrypted partition size (MB) : ' PDISKSZ
echo ""
echo "Conserity system option for the secret storage in the remote server(s) :"
echo "1) In one existing remote web server,"
echo "   configuration will be displayed."
echo "2) In several remote web servers, using Shamir shares,"
echo "   automatically setup at the VPS providers."
read -p 'Your choice : ' RemOpt

# Soon more options
#  Remote secret reading HTTPS or SSH
#  Multiple VPS providers
#  Service type : PHP, WSGI, local web server,...

# web, php, uwsgi
WebServiceType=web

# VPS Providers

# Remote Host
# Linode, ( DigitalOcean, Vultr, AWS, Scaleway )
if [ "$RemOpt" == '2' ]
then
  RemoteProvider01=linode

  if [ ! $LinodeAPIKey ]; then
    echo "LinodeAPIKey env var with your Linode APIv4 personal"
    echo "access token is required."
    echo "For example, use before starting run-conserity :"
    echo 'export LinodeAPIKey=YOURLINODEAPITOKEN ; history -d $(history 1)'
  exit 1
  fi

  echo ""
  read -p 'Total number of servers / shares (rec 4) : ' Nshares
  read -p 'Minimum shares requires (rec 3) : ' Krequired

  echo ""
  echo "Using $RemoteProvider01 VPS provider"
fi

# Initial update and clean up

echo ""
cmd_prt "System packages update"
apt-get -y upgrade >> $conserity_log_file
ok

# Installation of packages

cmd_prt "Install packages needed"
echo ""
apt-get -y -qq install certbot nginx-light ufw cryptsetup unzip wget >> $conserity_log_file
ok

# install docker-machine
if [ "$RemOpt" == '2' ]
then
  cmd_prt "Install docker-machine"
  if ! (type docker-machine &> /dev/null)
    then
    dmurl=https://github.com/docker/machine/releases/download/$DockerMachinev
    # ToDo : test against a hardcoded hash
    wget -q -O /tmp/docker-machine $dmurl/docker-machine-$(uname -s)-$(uname -m) &&
    mv /tmp/docker-machine /usr/local/bin/docker-machine &&
    chmod +x /usr/local/bin/docker-machine
  fi
  ok
fi

# Configure host for security

cmd_prt "Setup host for the security"

[ -f "/etc/sysctl.conf.OLD" ] || mv /etc/sysctl.conf /etc/sysctl.conf.OLD
cat <<EOF > /etc/sysctl.conf
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.eth0.disable_ipv6 = 1
EOF

[ -f "/etc/ssh/sshd_config.OLD" ] || mv /etc/ssh/sshd_config /etc/ssh/sshd_config.OLD
cat <<EOF > /etc/ssh/sshd_config
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
Port $SSHPORT
AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server
AddressFamily inet
X11Forwarding no
AllowAgentForwarding no
MaxAuthTries 4
KexAlgorithms curve25519-sha256@libssh.org
HostKeyAlgorithms ssh-ed25519,ssh-rsa
Ciphers aes256-gcm@openssh.com,aes256-ctr,chacha20-poly1305@openssh.com
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
AllowUsers root $fileUSER
PermitRootLogin prohibit-password
AllowTcpForwarding no
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no
ChallengeResponseAuthentication no
UsePAM no
PrintMotd no
EOF

rm -f /etc/ssh/ssh_host_*key*
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" < /dev/null >> $conserity_log_file
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" < /dev/null >> $conserity_log_file

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
certbot certonly --standalone --rsa-key-size 4096 --no-eff-email --must-staple -d $HOSTDOMAIN

[ -f "/etc/nginx/nginx.conf.OLD" ] || mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.OLD
cp -f conf/nginx.conf /etc/nginx/
sed -i "s/DOMAIN/${HOSTDOMAIN}/g" /etc/nginx/nginx.conf
cp -f conf/dhparam.pem /etc/nginx/
service nginx start >> $conserity_log_file
sleep 2
echo QUIT | openssl s_client -connect $HOSTDOMAIN:443 -tls1_2 -status > /dev/null
ok

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
ufw allow 443/tcp >> $conserity_log_file
ufw deny 80 >> $conserity_log_file
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
  echo " PASSWORD for user $fileUSER :"
  adduser $fileUSER
  ok
else
  ok "SKIPPED"
fi


# Create remote servers

if [ "$RemOpt" == '2' ]
then

  hostid=$(cat /etc/machine-id | sha256sum | cut -c1-8)
  nodename="conserity-$hostid-client0"

  # To Do : Manage partial installation of the machines
  #         Add user/password access
  #         Creation in parallel

  sec=($(eval "./shamir/split_secret.py $Krequired $Nshares"))

  CertsDIR=/usr/local/share/ca-certificates

  for srvi in $(seq $Nshares)
  do
    cmd_prt "Creating the remote server #${srvi} at Linode"
    ./vps-drivers/create-linode.sh $nodename$srvi
    ok
    cmd_prt "Setup remote server #${srvi}"
    IPDIST=$(docker-machine ip $nodename$srvi)
    remexec="docker-machine ssh $nodename$srvi"
    cat <<EOF > /tmp/Dockerfile
FROM nginx:alpine
RUN apk add --no-cache --update openssl
COPY nginx_docker.conf /etc/nginx/nginx.conf
COPY dhparam.pem /etc/nginx/dhparam.pem
COPY openssl.cnf openssl.cnf
RUN IPSRV=${IPDIST} openssl req -newkey rsa:4096 -config openssl.cnf -extensions v3_req -keyout /etc/nginx/privkey.pem -x509 -days 1460 -out /etc/nginx/cert_srv.pem
RUN echo ${sec[$srvi]} > /usr/share/nginx/html/index.html
RUN sed -i "s/IPHOST/${IPHOST}/g" /etc/nginx/nginx.conf
EOF
    sleep 4
    docker-machine scp /tmp/Dockerfile $nodename$srvi:~ >> $conserity_log_file
    docker-machine scp conf/nginx_docker.conf $nodename$srvi:~ >> $conserity_log_file
    docker-machine scp conf/openssl.cnf $nodename$srvi:~ >> $conserity_log_file
    docker-machine scp conf/dhparam.pem $nodename$srvi:~ >> $conserity_log_file
    $remexec sudo systemctl enable docker &>> $conserity_log_file
    $remexec sudo systemctl stop update-engine >> $conserity_log_file
    $remexec docker build -t mynginximage1 . >> $conserity_log_file
    $remexec docker run --restart always -p 443:443 --name mynginx -d mynginximage1 >> $conserity_log_file
    $remexec docker cp mynginx:/etc/nginx/cert_srv.pem cert_srv.pem
    docker-machine scp $nodename$srvi:~/cert_srv.pem ${CertsDIR}/cert_srv0${srvi}.crt >> $conserity_log_file
    ok
  done
  rm -f /tmp/Dockerfile

  # install the self-signed certificates of the remote servers
  update-ca-certificates --fresh >> $conserity_log_file

  # IP list of the client nodes
  # into a list used by getpwd

  fileIPclients=/root/ip_client
  echo ""
  cmd_prt "Creating the encrypted partition"

  docker-machine ip $(seq -f $nodename%1.f -s \  $Nshares) > $fileIPclients

  # test secret reading in the client servers
  if ! ( ./getpwd $fileIPclients &> /dev/null ) then
    echo "ERROR : issue with remote servers"
    exit 1
  fi

  echo "This can takes some time (5'000MB ~ 1min)"
  fallocate -l ${PDISKSZ}M /root/encryptdisk01
  shred /root/encryptdisk01
  echo ${sec[0]} | cryptsetup -q luksFormat /root/encryptdisk01 --pbkdf-memory 1024
  echo ${sec[0]} | cryptsetup luksOpen /root/encryptdisk01 volume1

fi

if [ "$RemOpt" == '1' ]
then
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

a=\`wget --user UserConsY --password $WEBACCESS --no-cache --no-cookies -q -U 'ag3nt12340pw38' -O- https://${WEBDOMAIN}/protect/${webfile}\`
echo \$a
EOF

fi


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
$PWD/getpwd $fileIPclients | /usr/sbin/cryptsetup luksOpen /root/encryptdisk01 volume1
mount /dev/mapper/volume1 /home/$fileUSER/protected_files
EOF

echo '@reboot  sleep 30 ; bash /root/mountsp.sh' >> /var/spool/cron/crontabs/root
echo -e "00 4 * * 1  certbot certonly --standalone  --rsa-key-size 4096 --force-renewal -n --pre-hook \"service nginx stop\" --post-hook \"service nginx start\" -d $HOSTDOMAIN" >> /var/spool/cron/crontabs/root
crontab /var/spool/cron/crontabs/root

ok

# Delete remote servers access
if [ "$RemOpt" == '2' ] # and HTTPS access
then 
  cmd_prt "Clean up"
  #rm -Rf ~/.docker/machine/machines/$nodename*
  ok
fi

sep
echo -e "Conserity configured everything successfully ! "
echo -e "\n !!! Your SSH link will display a warning about the server"
echo -e "     keys change, just update the server public key"
echo -e "     in your SSH client."
echo "SSHd will listen to port $SSHPORT"

if [ "$RemOpt" == '1' ]
then
  sep

  echo ""
  echo "Put in the the ${WEBDOMAIN} remote server :"
  echo "-  <WebRoot>/protect/$webfile file content (no line return) :"
  echo $PASSWORD
  echo ""
  echo "and additionally in that remote \"protect\" directory :"
  echo "-  .htpasswd file content :"
  echo "UserConsY:$(openssl passwd -apr1 --salt s4lto932 $WEBACCESS)"
  echo ""
  echo "-  .htaccess file content :"
  echo "AuthUserFile /<PATH/TO/WebRoot>/protect/.htpasswd"
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
fi

echo -e "\nYour web service socket has to listen to"
echo -e "localhost port 9090."

echo "A ${PDISKSZ} MB encrypted partition is mounted on"
echo "/home/${fileUSER}/protected_files/"
echo ""
echo "It will be automatically mounted at every boot,"
echo "reading the secret from the remote server(s)."

echo -e "\nYou can reboot the machine to finish the installation"

sep
echo ""
