#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Conserity : Shamir Share generation and split
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


import shamir
import base64
import sys
import secrets

if __name__ == "__main__":
	assert len(sys.argv) == 3, "Requires k n arguments"
	n = int(sys.argv[2])
	k = int(sys.argv[1])
	
	# Generate secrets
	seed = secrets.token_bytes(32)
	print(base64.b64encode(seed).decode("ascii"))
	
	# Split using Shamir secret share
	shares = shamir.split_secret(seed, k, n)
	sharesb64 = list(map(base64.b64encode,shares))
	for share in sharesb64:
		print(share.decode("ascii"))

