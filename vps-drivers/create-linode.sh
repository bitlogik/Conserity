#!/bin/bash -e

# Conserity : Manage Linode VPS to install a machine
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

# Requires LinodeAPIKey env variable

# Install the docker-machine driver for Linode
# Only if wasn't done before

DMLinodev=v0.1.8

if ! ( type docker-machine-driver-linode &> /dev/null )
then
  # Linode driver
  echo -e "\nInstalling Linode driver"
  wget https://github.com/linode/docker-machine-driver-linode/releases/download/$DMLinodev/docker-machine-driver-linode_linux-amd64.zip &> /dev/null
  test_file docker-machine-driver-linode_linux-amd64.zip b31b6a504c59ee758d2dda83029fe4a85b3f5601e22dfa58700a5e6c8f450dc7
  unzip -qq docker-machine-driver-linode_linux-amd64 -x *.md LICENSE
  mv docker-machine-driver-linode /usr/local/bin/docker-machine-driver-linode && chmod +x /usr/local/bin/docker-machine-driver-linode
fi

docker-machine create -d linode --linode-token=$LinodeAPIKey --linode-region eu-central --linode-image=linode/containerlinux --linode-instance-type g6-nanode-1 $1
