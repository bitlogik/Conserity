#!/bin/bash -e

# Conserity : Testing adding server
# Copyright (C) 2020  BitLogiK
#
# Conserity script test
# For Debian and Ubuntu

conserity_log_file="log/output.log"

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

apt-get -y update
apt-get -y upgrade
apt-get -y install wget unzip

echo "Install docker-machine"
DockerMachinev=v0.16.2

if ! (type docker-machine &> /dev/null)
  then
  dmurl=https://github.com/docker/machine/releases/download/$DockerMachinev
  wget -q -O /tmp/docker-machine $dmurl/docker-machine-$(uname -s)-$(uname -m)
  test_file /tmp/docker-machine a7f7cbb842752b12123c5a5447d8039bf8dccf62ec2328853583e68eb4ffb097
  mv /tmp/docker-machine /usr/local/bin/docker-machine
  chmod +x /usr/local/bin/docker-machine
fi

IPHOST=$(ip route get 1 | sed -n 's/^.*src \([0-9.]*\) .*$/\1/p')

sec="ABCD 01"

CertsDIR=/usr/local/share/ca-certificates
hostid=$(cat /etc/machine-id | sha256sum | cut -c1-8)
nodename="conserity-$hostid-clientTst"

Nshares=3

srvi=1
echo -e "\nAt which VPS cloud provider would you set the #${srvi} server ?"
echo " 1) Digital Ocean"
echo " 2) Linode"
echo " 3) Scaleway"
read -p ' Choice : ' ProvChoice
case $ProvChoice in
"1")
	ProvName="Digital Ocean"
	ProvScript=do
	;;
"2")
	ProvName="Linode"
	ProvScript=linode
	;;
"3")
	ProvName="Scaleway"
	ProvScript=sw
	;;
esac
read -p " Input your ${ProvName} API key : " APIKey
cmd_prt "Creating the remote server #${srvi} at ${ProvName}"
export -f test_file
./vps-drivers/create-${ProvScript}.sh $nodename$srvi $APIKey
ok
cmd_prt "Setup remote server #${srvi}"
IPDIST=$(docker-machine ip $nodename$srvi)
remexec="docker-machine ssh $nodename$srvi"
if (cat /etc/os-release | grep -E "Ubuntu" > /dev/null) then
  cp conf/DockerfileUb /tmp/Dockerfile
else
  cp conf/Dockerfile /tmp/Dockerfile
fi
export sec srvi IPDIST IPHOST
envsubst < /tmp/Dockerfile
sleep 4
docker-machine scp /tmp/Dockerfile $nodename$srvi:~
docker-machine scp conf/nginx_docker.conf $nodename$srvi:~
docker-machine scp conf/openssl.cnf $nodename$srvi:~
docker-machine scp conf/dhparam.pem $nodename$srvi:~
$remexec sudo systemctl enable docker
$remexec sudo systemctl stop update-engine || :
$remexec docker build -t mynginximage1 .
$remexec docker run --restart always -p 443:443 --name mynginx -d mynginximage1
$remexec docker cp mynginx:/etc/nginx/cert_srv.pem cert_srv.pem
docker-machine scp $nodename$srvi:~/cert_srv.pem ${CertsDIR}/cert_srv0${srvi}.crt
ok
rm -f /tmp/Dockerfile
APIKey=" "
sleep 1
update-ca-certificates --fresh
sleep 2
wget -O - "https://${IPDIST}"
