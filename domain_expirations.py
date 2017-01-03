#!/usr/bin/env python

# This is a cron-friendly script to parse domain expiration dates from
# whois output, and warn if any domains are getting close to expiring.
#
# It gets a list of domains to check from a BIND-format zone file,
# which it expects to find in /var/lib/named/etc/bind/bind.local.
#
# The whois info format depends on your domain registrar.  This script
# attempts to understand several common ones, but the regexes have
# a history of being fragile.  Also, some whois servers aggressively
# rate-limit queries which may cause problems.


import os
import re
import time

extradomains = []

def zones(f):
	z = []
	p = re.compile(r'\s*zone\s*"(.*)"\s*{', re.IGNORECASE)
	for line in f:
		m = p.match(line)
		if m:
			domain = m.group(1)
			if re.search('.ip6.arpa', domain):
				continue
			z.append(domain)
	return z

def domain_expiration(domain):
	tucows_p = re.compile('Registrar Registration Expiration Date: (.*) ')
	godaddy_p = re.compile('      Expires on: (.*)')
	org_p = re.compile('Registry Expiry Date: (.*)')
	us_p = re.compile('Domain Expiration Date:\\s*(.*)')

	#f = open('whois/'+domain)
	f = os.popen4('whois '+domain)[1]
	for line in f:
		line = line.rstrip()

		m = tucows_p.match(line)
		if m:
			s = m.group(1)
			return time.strptime(s + ' UTC', '%Y-%m-%d %Z')
		m = godaddy_p.match(line)
		if m:
			s = m.group(1)
			return time.strptime(s + ' UTC', '%d-%b-%y %Z')
		m = org_p.match(line)
		if m:
			s = m.group(1)
			return time.strptime(s, '%Y-%m-%dT%H:%M:%SZ')
		m = us_p.match(line)
		if m:
			s = m.group(1)
			return time.strptime(s, '%a %b %d %H:%M:%S %Z %Y')

	return time.gmtime(0)

def time_within_months(t, m):
	# WRONG:  We want mktime to treat its struct_time as UTC, but
	# there's no way to do that without playing tiddlywinks with
	# os.environ['TZ'].
	#
	# mktime takes a structure which contains a dst flag but no
	# zone information.  Thank you, Python, for perpetuating that
	# particular piece of ANSI C fuckage.

	then = time.mktime(t)
	now = time.time()
	return then - now <= m * 30 * 86400

def iso_date(t):
	return time.strftime('%Y-%m-%d', t)

def print_expirations(domains):
	expirations = zip(map(domain_expiration, domains), domains)
	expirations.sort()

	for n in 1, 3, 6, 12:
		e = []
		while expirations and time_within_months(expirations[0][0], n):
			e.append(expirations[0])
			del(expirations[0])
		if len(e):
			print 'These domains will expire within %d months:' % n
			for t, domain in e:
				print '\t' + domain.ljust(35) + iso_date(t)
			print
	print 'These domains will expire in >12 months:'
	for t, domain in expirations:
		print '\t' + domain.ljust(35) + iso_date(t)

def main():
	domains = zones(file('/var/lib/named/etc/bind/named.conf.local'))
	domains.extend(extradomains)
	#print domains
	print_expirations(domains)

if __name__ == '__main__':
	main()
