#!/usr/bin/python
# -*- coding: utf-8 -*-
#------------------------------------------------------------------------------------------------
#Description: Ferramenta que obtem URL's associados a um determinado IP
#Version:1.
#Author: Helder Miguel Fernandes<helder.fernandes1279@gmail.com>
#ScriptName:iptoUrl.py
#Lib requirements: BeautifulSoup
#------------------------------------------------------------------------------------------------

from __future__ import with_statement
import re, sys, os, shlex,urllib2,time,os,StringIO
from time import gmtime, strftime
from urlparse import urlparse
from BeautifulSoup import BeautifulSoup as bs






def get_urls_bgp(ip):
 request = urllib2.Request("http://bgp.he.net/ip/%s" %ip)
 request.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)')
 bgp = bs(urllib2.urlopen(request))
 wls = []
 websiteslist = []
 for dn in bgp('a'):
  if re.match('/dns/',dn['href']):
    wls.append(dn.string)
    
 for website in wls:
   websiteslist.append("http://"+website)

 return websiteslist

def get_urls_robtex(ip):
 request = urllib2.Request("http://ip.robtex.com/%s.html" % ip)
 request.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)')
 robtex = bs(urllib2.urlopen(request))
 websiteslist = []
 tmp=robtex.findAll("span",{"id":re.compile("dns")})

 a=bs(str(tmp))

 for url in a('a'):
   websiteslist.append("http://"+url.string)
 
 return websiteslist

if(len(sys.argv) == 1 or len(sys.argv)>2):
 print "usage:\niptoUrl.py <ip address>"
else:
 ip=sys.argv[1]
 list1=get_urls_bgp(ip)
 list2=get_urls_robtex(ip)
 urllist=[]
 for ln in list1:
  urllist.append(ln)
 for ln in list2:
  urllist.append(ln)

 sorted_url=list(set(urllist))
 sorted_url.sort()
                
 for t in sorted_url:
  print t




