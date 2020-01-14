#!/bin/bash -e

# Conserity : Manage Digital Ocean VPS to install a machine
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

docker-machine create -d digitalocean --digitalocean-access-token $2 --digitalocean-image coreos-stable --digitalocean-region fra1 --digitalocean-size s-1vcpu-1gb --digitalocean-backups=false --digitalocean-ssh-user core $1
