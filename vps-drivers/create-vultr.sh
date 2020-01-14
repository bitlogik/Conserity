#!/bin/bash -e

# Conserity : Manage Vultr VPS to install a machine
# Copyright (C) 2020  BitLogiK
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

# Install the docker-machine driver for Vultr
# Only if wasn't done before
DMVLTRv="v1.4.0"

if ! ( type docker-machine-driver-vultr &> /dev/null )
then
  # Vultr driver
  echo -e "\nInstalling Vultr driver"
  wget https://github.com/janeczku/docker-machine-vultr/releases/download/${DMVLTRv}/docker-machine-driver-vultr-Linux-x86_64 &> /dev/null
  test_file docker-machine-driver-vultr-Linux-x86_64 46bc306ed8dc4c301b06352db370605bd589da9957565a03dc81a44b5d4788c0
  mv docker-machine-driver-vultr-Linux-x86_64 /usr/local/bin/docker-machine-driver-vultr && chmod +x /usr/local/bin/docker-machine-driver-vultr
fi

docker-machine create -d vultr --vultr-api-key=$2 --vultr-region-id=9 --vultr-os-id=179 --vultr-plan-id=201 $1 || :
docker-machine stop $1 || :
docker-machine start $1 || :
docker-machine start $1 || :
sleep 10
docker-machine regenerate-certs -f $1
