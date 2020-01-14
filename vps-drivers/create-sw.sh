#!/bin/bash -e

# Conserity : Manage Scaleway VPS to install a machine
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

# Install the docker-machine driver for Scaleway
# Only if wasn't done before
DMSWv="1.6"

if ! ( type docker-machine-driver-scaleway &> /dev/null )
then
  # Scaleway driver
  echo -e "\nInstalling Scaleway driver"
  wget https://github.com/scaleway/docker-machine-driver-scaleway/releases/download/v${DMSWv}/docker-machine-driver-scaleway_${DMSWv}_linux_amd64.tar.gz &> /dev/null
  test_file docker-machine-driver-scaleway_${DMSWv}_linux_amd64.tar.gz 102df7f8b37ce2cfa0eaea7d395bb4b626b2b3df0334c6b000b3565e39732ece
  tar xzf docker-machine-driver-scaleway_${DMSWv}_linux_amd64.tar.gz docker-machine-driver-scaleway
  mv docker-machine-driver-scaleway /usr/local/bin/docker-machine-driver-scaleway && chmod +x /usr/local/bin/docker-machine-driver-scaleway
fi

# Get the Organization UID
OrgID=$(wget -q -O - https://account.scaleway.com/organizations --header "X-Auth-Token: $2"| python3 -c 'import json,sys;obj=json.load(sys.stdin);print(obj["organizations"][0]["id"])')

docker-machine create -d scaleway --scaleway-token=$2 --scaleway-region "par1" --scaleway-organization $OrgID --scaleway-image=docker --scaleway-commercial-type=DEV1-S --scaleway-name=$1 $1

