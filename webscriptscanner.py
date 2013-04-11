#!/usr/bin/python
# -*- coding: utf-8 -*-
#------------------------------------------------------------------------------------------------
#Description: Ferramenta que efectua scan aos scripts dos websites, procura padrões especificados
#no ficheiro de assinaturas (yara.sig)
#Version:1.
#Author: Helder Miguel Fernandes<helder.fernandes1279@gmail.com>
#ScriptName:WebScriptscanner.py
#Lib requirements: BeautifulSoup, yara
#------------------------------------------------------------------------------------------------

from __future__ import with_statement
import re, sys, os, shlex,urllib2,time,os,StringIO,yara,socket,httplib,commands,socket
from time import gmtime, strftime
from urlparse import urlparse
from BeautifulSoup import BeautifulSoup as bs
from zipfile import ZipFile, ZIP_DEFLATED
from contextlib import closing

default_timeout = 10

socket.setdefaulttimeout(default_timeout)

def zip_files(folder,reportpath,archive,password):
 os.chdir(reportpath)
 os.popen("zip -P %s -r %s %s" % (password,archive,folder))



def get_redirect_status(host,referer):
    """ Funcao que retorna o status http
    """
    if(host.find('/')>0):
     host=host[:host.find('/')]

    try:
        conn = httplib.HTTPConnection(host)

        headers = {"User-Agent":"Mozilla/4.0 (compatible; MSIE 7.0; Windows; Windows NT 5.1)","Referer": referer}
   
        conn.request("GET", "/","",headers)
        result=conn.getresponse()
        return result
    except StandardError, e:
        print "%s" % str(e)
        return None
    
def scan_redirect(url,report):

   redirect_strings=['http://www.google.com/url?sa','http://search.aol.com/aol/search','http://search.yahoo.com/search','http://www.bing.com/search']
   detected=False
   for line in redirect_strings:
    URL_status=get_redirect_status(url.replace('http://',''),line)
    if not URL_status is None:
     if URL_status.status==301 or URL_status.status==302:
      for ln in URL_status.getheaders():
       if(re.search('location',ln[0])):
        if not (re.search(url,ln[1])):
         detected=True
         if re.search('google',line):
          print 'Google redirect detected -> %s:%s ' % (ln[0],ln[1])
          report.write('\nGoogle redirect detected -> %s:%s' % (ln[0],ln[1]))
	 if re.search('aol',line):
          print 'Aol redirect detected -> %s:%s ' % (ln[0],ln[1])
          report.write('\nAol redirect detected -> %s:%s ' % (ln[0],ln[1]))
	 if re.search('yahoo',line):
          print 'Yahoo redirect detected -> %s:%s ' % (ln[0],ln[1])
          report.write('\nYahoo redirect detected -> %s:%s ' % (ln[0],ln[1]))
         if re.search('bing',line):
          print 'Bing redirect detected -> %s:%s ' % (ln[0],ln[1])
          report.write('\nBing redirect detected -> %s:%s ' % (ln[0],ln[1]))

   return detected
    

#funções que retornam a lista de urls registada no bgp e robtex

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
   if not url.string is None:
    websiteslist.append("http://"+url.string)
 
 return websiteslist



def get_urls_by_ip(ip):
 list1=get_urls_bgp(ip)
 list2=get_urls_robtex(ip)
 urllist=[]
 for ln in list1:
  urllist.append(ln)
 for ln in list2:
  urllist.append(ln)
 sorted_url=list(set(urllist))
 sorted_url.sort()               
 return sorted_url


#função que recebe o url e faz um scan aos scripts do mesmo e escreve num ficheiro os scripts detectados como maliciosos

def scan_website(url,rules,report,files_path):
  detected=False
  contenttype="http"
  request = urllib2.Request("%s" % url)
  request.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)')
  url_report=open(report_path+'/detected_urls.txt','a')
  try:
   URL_status=get_redirect_status(url.replace('http://',''),url)
   if not URL_status is None:
    if URL_status.status==301 or URL_status.status==302:
     for ln in URL_status.getheaders():
      if(re.search('location',ln[0])):
       if not (re.search(url.replace('http://',''),ln[1])):
	if(re.search('http://',ln[1])):
	 print "\n"+url+" redirects to %s, scanning redirect location" %ln[1]
	 report.write("\n"+url+" redirects to "+ln[1]+", scanning redirect location") 
	 report.write("\n"+ln[1]+"\n") 
	 url=ln[1]
         request = urllib2.Request("%s" % url)
         request.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)')
   urlresponse=urllib2.urlopen(request)
   website = urlresponse.read()
   domain=url.replace('http://','')
   if(domain.find('/')>0):domain=domain[:domain.find('/')]
   if(domain.find(':')>0):domain=domain[:domain.find(':')]
   host_ip=socket.gethostbyname(domain)
   print "\n%s [%s]" % (url,host_ip)
   report.write("\n%s [%s]\n" % (url,host_ip))
   pattern=re.compile("</script>",re.IGNORECASE)
   website=pattern.sub("</script>\n",website)
   pattern=re.compile("<script>",re.IGNORECASE)
   website=pattern.sub("<script>",website)
   buf = StringIO.StringIO(website)
   script_sources=""
   if(re.search('x-javascript',urlresponse.info().getheader('Content-Type'))):
     result=script_scanner(rules,website)
     if(result!=0):
      print "--%s found in JSFfile" % (result)
      report.write("--%s found in JSFile\n" % (result))
      contenttype="JS"
      detected=True
      fullsite=website
   else:
    website=buf.readlines()
    fullsite=""
    for l in website:
     fullsite+=l
    scripts=get_scripts(website)
    script_sources=get_script_sources(url,get_scripts(website))
    detected_count=0;
    for line in scripts:
     result=script_scanner(rules,line)
     if(result!=0):
	  detection=result
	  detected_count=detected_count+1
	  detected=True
    
      
   if(detected==True):  
    print "--"+str(detection)+" found in root - %d time(s)" % (detected_count)
    report.write("--"+str(detection)+" found in root - %d time(s)\n" % (detected_count))
    dirname=url[7:]
    dirname=dirname.replace('/','_')
    if not os.path.isdir(files_path):
     os.mkdir(files_path)
    if not os.path.isdir(os.path.join(files_path, dirname)):
     os.mkdir(os.path.join(files_path, dirname))
    url_report.write(url+"\n")
    if(contenttype=='JS'): 
     f=open(os.path.join(files_path,dirname)+'/'+dirname[dirname.rfind('_')+1:],'w')
    else:
     f=open(os.path.join(files_path,dirname)+'/'+'index.html','w')
    f.write(fullsite)
    f.close()
    
   for line in script_sources:
    script_request = urllib2.Request("%s" % line)
    script_request.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)')
    try:
     script_file=(urllib2.urlopen(script_request)).read()
     result=script_scanner(rules,script_file)
     if(result!=0):
      print "%s --> %s" % (result,line)
      report.write("%s --> %s\n" % (result,line))
      url_report.write(line+" \n")
      detected=True
      dirname=url[7:]
      dirname=dirname.replace('/','_')
      if not os.path.isdir(files_path):
       os.mkdir(files_path)
      if not os.path.isdir(os.path.join(files_path, dirname)):
       os.mkdir(os.path.join(files_path, dirname))
      path = os.path.join(files_path,dirname)+line[line.rfind('/'):]
      try:
       f=open(path,'w')
       f.write(script_file)
       f.close()  
      except IOError as e:
       print "Could not save file  reason ->%s" %str(e)
       report.write("Could not save file\n")
    except urllib2.URLError, e:
     print "--Cannot not open %s\n" % (line)
     report.write("--Cannot not open %s\n" % (line))
     e=''
    except urllib2.HTTPError, e:
     print "--Cannot not open %s\n" % (line)
     report.write("--Cannot not open %s\n" % (line))
     e=''
    except httplib.HTTPException, e:
     print "--Cannot not open %s\n" % (line)
     report.write("--Cannot not open %s\n" % (line))
     e=''
   url_report.close()
  except urllib2.URLError, e: 
   print "Cannot open %s\n" % (url)
   report.write("Cannot open %s\n" % (url))
  except socket.timeout, e:
   print "Cannot open %s\n" % (url)
   report.write("Cannot open %s\n" % (url))
  except socket.error, e:
   print "Cannot open %s\n" % (url)
   report.write("Cannot open %s\n" % (url))
  return detected







#funcao que recebe o site num array de linhas e devolve todos os scripts existentes

def get_scripts(originalwebsite):
 scripts = []
 sizeofweb=len(originalwebsite)
 x=0
 y=-1
 insidescript=0
 website = []
 for line in originalwebsite:
  website.append(line.lower())

 while(x < sizeofweb):
  if(insidescript==1 and not re.search('/script>',website[x])):
    scripts[y]+=website[x]  
  if((re.search('/script>',website[x]) or re.search('/script-->',website[x])) and insidescript==1):
    scripts[y]+=website[x][:website[x].find('/script>')+8]
    insidescript=0
  if(re.search('<script',website[x])):
   if(re.search('<script',website[x]) and (re.search('/script>',website[x]) or re.search('/script-->',website[x]))):
    low=website[x].find('<script')
    high=website[x].find('/script>')+8
    scripts.append(website[x][low:high])
    y+=1
   else: 
    scripts.append(website[x][website[x].find('<script'):])
    insidescript=1
    y+=1
  x+=1 
 return scripts 

def get_script_sources(url,scripts):
 sources=[]

 for line in scripts:
   if(line.lower().find(' src=') > -1 and line.lower().find('.js') > 1  and line.lower().find('function()') < 0 and line.lower().find('location.hostname') < 0 and line.lower().find('google-analytics') < 0 and line.lower().find('googleapis') < 0 and re.search(' src=\'http://',line.lower()) < 0 and re.search('src="http://',line.lower()) < 0 and re.search('src=%27http://',line.lower()) < 0 and re.search('src="https://',line.lower()) < 0 and re.search(' src=\'https://',line.lower()) < 0 and re.search('src=%27https://',line.lower()) < 0):
    low=line.lower().find('src=')+5
    high=line.lower().find('.js')+3
    if(line[low]!='/'):
     sources.append(url+'/'+line[low:high])
    elif(line[low]=='/' and line[low+1]=='/'):
     sources.append('http:'+line[low:high])
    else: 
     sources.append(url+line[low:high])
   
   if((re.search(' src=\'http://',line.lower()) > -1 or re.search(' src="http://',line.lower()) or re.search(' src=\'https://',line.lower()) > -1 or re.search(' src=\'https://',line.lower()) > -1) and line.lower().find('googleapis') < 0 and line.lower().find('location.hostname') < 0 and line.lower().find('google-analytics') < 0 and line.lower().find('.js') > 1 and line.lower().find('function') < 0):

     low=line.lower().find('src=')+5
     high=line.lower().find('.js')+3
     sources.append(line[low:high])
     
 
 return sources


def script_scanner(yara_rules,script):
  result=yara_rules.match(data=script)
  if(len(result)==0):
   return 0

  return result

#main do código


settings_file=open(sys.argv[0][:sys.argv[0].rfind('/')]+'/settings.conf')
settings=settings_file.readlines()

for line in settings:
 line=line.replace('\n','')
 if(re.search('reports_path=',line)):
  report_path=line[line.rfind('=')+1:]
 
settings_file.close()
if not os.path.isdir(report_path):
 os.mkdir(report_path)



rules=yara.compile(sys.argv[0][:sys.argv[0].rfind('/')]+'/yara.sig')


redirect=False
idspec=False
badparameter=0

scantime=strftime("%Y%m%d-%H%M%S", time.localtime())
formatedscantime=strftime("%Y-%m-%d %H:%M:%S", time.localtime())



if(len(sys.argv) == 1):
 print "usage:" 
 print "malwebscanner.py [options] [Referer Test] [case ID]"
 print "=========================================="
 print "[Options]:"
 print "-u url            -> scan url"
 print "-ip Ip_Address    -> scan all websites from Ip_Address (BGP reference)"
 print "-l file           -> scan all websites in file"
 print "=========================================="
 print "[Redirect Test]:"
 print "-r		  -> Referer Test enabled"
 print "=========================================="
 print "[case ID]:"
 print "-id caseid	  -> Set caseID directory"
 sys.exit()
else:
 report_logs=open(report_path+'/folder.log','a')
 if(len(sys.argv)>3 and len(sys.argv)<6):
  if(sys.argv[3]=='-r'):
   redirect=True
   report=open(report_path+'/report-'+scantime+'.txt','a')
  elif(sys.argv[3]=='-id'):
   caseid=sys.argv[4]
   idspec=True
   report_path=report_path+"PSI-"+caseid+"-ID/"
   if not os.path.isdir(report_path):
    os.mkdir(report_path)
   report=open(report_path+'/report-'+caseid+'.txt','a')
  else:badparameter=-1
 elif(len(sys.argv)>5):
  if(sys.argv[4]=='-id'):
   caseid=sys.argv[5]
   idspec=True
   report_path=report_path+"PSI-"+caseid+"-ID/"
   if not os.path.isdir(report_path):
    os.mkdir(report_path)
   report=open(report_path+'/report-'+caseid+'.txt','a')

  else:badparameter=-1
 
 if((redirect==True and idspec==False) or (redirect==False and idspec==False)):
  report_path=report_path+scantime+"/"
  if not os.path.isdir(report_path):
    os.mkdir(report_path)
  report=open(report_path+'/report-'+scantime+'.txt','a')
 report.write("\n==========Analysis started at "+formatedscantime+"======================\n") 

 if sys.argv[1]=='-u' and badparameter==0:
  report_logs.write(scantime+";"+sys.argv[2]+"\n")
  report_logs.close()
  if(re.search('http://',sys.argv[2])):
   
   detected=scan_website(sys.argv[2],rules,report,report_path+'Files/')
   if(detected==True):
    print "Web site is infected"
    report.write("\nWeb site is infected\n")
   if(redirect==True):
    redirectscan=scan_redirect(sys.argv[2][7:],report)
  else:
   detected=scan_website("http://"+sys.argv[2],rules,report,report_path+'Files/')
   if(detected==True):
    print "Web site is infected"
    report.write("\nWeb site is infected\n")
   if(redirect==True):
    redirectscan=scan_redirect(sys.argv[2],report)
  if(os.path.isdir(report_path+"Files/")):
   if not(os.listdir(report_path+"Files/")==[]): 
    if(idspec==True):archivename=caseid
    else:archivename=scantime
    zip_files("./Files",report_path,"Sample-"+archivename+".zip","infected")
 
 elif sys.argv[1]=='-ip' and badparameter==0:
  report_logs.write(scantime+";"+sys.argv[2]+"\n")
  report_logs.close()
  websites=get_urls_by_ip(sys.argv[2])
  x=0
  for website in websites:
   detected=scan_website(website,rules,report,report_path+'Files/')
   if(detected==True):
    x+=1
   if(redirect==True):
    redirectscan=scan_redirect(website[7:],report)
  print "Found %s sites infected" % x
  report.write("\nFound %s sites infected\n" % x)
  if(os.path.isdir(report_path+"Files/")):
   if not(os.listdir(report_path+"Files/")==[]): 
    if(idspec==True):archivename=caseid
    else:archivename=scantime
    zip_files("./Files",report_path,"Sample-"+archivename+".zip","infected")
 
 elif sys.argv[1]=='-l' and badparameter==0:
  report_logs.write(scantime+";list from file "+sys.argv[2]+"\n")
  report_logs.close()
  f = open(sys.argv[2], "r")
  url_list = f.readlines()
  f.close()
  x=0
   
    
  while(x < len(url_list)):
   if not (re.search('http://',url_list[x])):
    url_list[x]='http://'+url_list[x]
   url_list[x]=url_list[x].replace("\n","")
   x+=1
  y=0
  for url in url_list: 
   detected=scan_website(url,rules,report,report_path+'Files/')
   if(detected==True):
    y+=1
   if(redirect==True):
    redirectscan=scan_redirect(url[7:],report)
  print "Found %s sites infected" % y
  report.write("\nFound %s sites infected\n" % y)
  if(os.path.isdir(report_path+"Files/")):
   if not(os.listdir(report_path+"Files/")==[]):
    if(idspec==True):archivename=caseid
    else:archivename=scantime
    zip_files("./Files",report_path,"Sample-"+archivename+".zip","infected") 
 else:
  print "usage:" 
  print "malwebscanner.py [options] [Redirect Test] [case ID]"
  print "=========================================="
  print "[Options]:"
  print "-u url            -> scan url"
  print "-ip Ip_Address    -> scan all websites from Ip_Address (BGP reference)"
  print "-l file           -> scan all websites in file"
  print "=========================================="
  print "[Redirect Test]:"
  print "-r		  -> Redirect Test enabled"
  print "=========================================="
  print "[case ID]:"
  print "-id caseid	  -> Set caseID directory"
  report.close()
  sys.exit()

report.close()



 
 
 













