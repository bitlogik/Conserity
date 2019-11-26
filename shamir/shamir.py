#
# -*- coding: utf-8 -*-

# Conserity : Shamir Share Python3 library
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

import secrets

Prime = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

def _divmod( b, a, m ):
	# return b*1/a mod m (for m prime)
	if a < 0 or m <= a: a=a%m
	u, v = a,m
	xa,xb = 1,0
	while u != 1:
		q,r = divmod(v,u)
		x = xb-q*xa
		v,u,xb,xa = u,r,xa,x
	return (b*xa)%m

def eval_at(polynomial, x, prime):
	y = 0
	for coeff in reversed(polynomial):
		y *= x
		y += coeff
		y %= prime
	return y.to_bytes(32, byteorder='big')

def compute_y0(x_s, y_s, p):
	k = len(x_s)
	res = 0
	for i in range(k):
		others = list(x_s)
		cur = others.pop(i)
		nums, dens = 1, 1
		for o in others:
			nums *= o
			dens *= o - cur
		res += _divmod(y_s[i]*nums, dens, p)
	return res % p

def split_secret(secret, k, n, prime=Prime):
	assert len(secret) == 32, "Needs a 32 bytes secret"
	assert n < 256, "N can't be higher than 256"
	assert k <= n, "K can't be higher than N"
	sint = int.from_bytes(secret, byteorder='big')
	polynomial = [ sint ] + [ secrets.randbelow(prime) for i in range(k-1) ]
	shamir_data = [ bytes([i]) + eval_at(polynomial, i, prime) for i in range(1, n + 1) ]
	return shamir_data

def recover_secret(shares, prime=Prime):
	if len(shares) < 2:
		raise Exception("Needs at least 2 shares.")
	x_s, y_s = zip(*shares)
	return compute_y0(x_s, y_s, prime)

def read_shares(sharesbin):
	shares = []
	for share in sharesbin:
		shares.append([share[0], int.from_bytes(share[1:], byteorder='big')])
	return recover_secret(shares).to_bytes(32, byteorder='big')

