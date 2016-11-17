

import urllib2
import rssParser
import pprint

#url_info = urllib2.urlopen('https://feodotracker.abuse.ch/feodotracker.rss')

d = rssParser.parse('https://feodotracker.abuse.ch/feodotracker.rss')


pp = pprint.PrettyPrinter(indent=4)

print len(d['entries'])

#pp.pprint(d['entries'])
# i = 0
# for sKey in d:
# 	pp.pprint(d[sKey])
# 	if i > 5:
# 		break
# 	i += 1		