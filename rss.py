#!/bin/python3
# @author Karim HAROUAT
# CVE parser
from ast import Store
from os import link
import string
import feedparser
import argparse
import validators
import os
from lxml import etree, html
import json
import requests
import zipfile as ZF
import tempfile as tmpfile


def type_url(strurl):
    if validators.url(strurl):
        return strurl
    else:
        raise argparse.ArgumentTypeError("Should be an real web link")

def type_file(filename):
    if os.path.isfile(filename):
        return filename
    else:
        raise argparse.ArgumentTypeError("Should be an existing file")

class JsonContent:
    def __init__(self, filesource):
        self.json_content = None
        if os.path.isfile(filesource):
            content_file = open(filesource,'r')
            self.json_content = json.load(content_file)
            content_file.close()
        else:
            self.json_content = json.loads(filesource)
    
    def content(self):
        return self.json_content
    def size(self):
        return len(self.json_content['CVE_Items'])

def get_nist_json(date=None):
    cveperiod="recent"
    if date != None:
        year=str(date).split('-')[0]
        if year.isdigit() and int(year)>1000 :
            cveperiod=year    
    url="https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-"+cveperiod+".json.zip"
    zfile_name="nvdcve-1.1-"+cveperiod+".json.zip"
    try:
        response=requests.get(url)
        local=tmpfile.NamedTemporaryFile('wb')
        local.write(response.content)
        data=ZF.ZipFile(str(local.name))
        data_to_return=data.read("nvdcve-1.1-"+cveperiod+".json")
        data.close()
        local.close()
        return data_to_return
    except Exception as e:
        print(f"try to get {url} but failed, error {str(e)}")
        exit(1)


def print_entry_keys(url):
    try:
        if type(url)==str and ("cert" in url or "mitre" in url):
            print("Reading cert xml file")
            NewsFeed = feedparser.parse(url)
            entry = NewsFeed.entries[0]
            print(entry)
        else:            
            print("Reading nist json file")
            NewsFeed = JsonContent(url).content()
            first=NewsFeed['CVE_Items'][0]['cve']['CVE_data_meta']['ID']
            print(first)
    except Exception as e:
        print(e)
        print("Link is bad or not rss feed so that no keys attribute ")

def print_cert_details(entry,showlink=False,verbose=False):    
    if verbose:
        try:
            text =  html.fromstring(entry.summary).text_content()
        except:
            text = "Nothing found"
        print(text)
    try:
        link = entry.links
    except:
        link = "Entry has no links attribute"
        print("link error")
    try:
        mystring=str(entry.links[0]).replace('\'','"')
        data = json.loads(mystring)
        link = data['href']
    except:
         print("Href was not found")
    if verbose or showlink:
        print(link)
    if verbose or showlink:
        print("==============================")

def print_nist_details(entry,showlink=False,verbose=False):    
    if verbose:
        try:
            text =  entry['cve']['description']['description_data'][0]['value']
        except:
            text = "Nothing found"
        print(text)
    try:
        link = entry['cve']['references']['reference_data'][0]['url']
    except:
        link = "Entry has no links attribute"
        print("link error")
    if verbose or showlink:
        print(link)
    if verbose or showlink:
        print("==============================")        

def print_cert_entry(url, nb_entry,keyword=None,keydate=None,severity=None,showlink=False,verbose=False,quiet_on_error=False):
    NewsFeed = feedparser.parse(url)
    NewsFeed_size=len(NewsFeed.entries)
    print ("There are " + str(NewsFeed_size) +" entries")
    print("******************************\n\n")
    r=nb_entry
    if nb_entry == 0:
        r=NewsFeed_size
    if (r >  NewsFeed_size):
        print("You want too much data more than real entries")
        r = NewsFeed_size
    for i in range(r):
        try:
            entry = NewsFeed.entries[i]
            if keyword is not None:
                if (entry.title.lower().find(keyword.lower()) == -1) and (entry.summary.lower().find(keyword.lower()) == -1):
                    continue
            if severity is not None:
                if (entry.title.lower().find(severity.lower()) == -1) and (entry.summary.lower().find(severity.lower()) == -1):
                    continue
            if keydate is not None:
                if (entry.title.lower().find(keydate.lower()) == -1) :
                    continue
            print(entry.title)
            print_cert_details(entry,verbose=verbose,showlink=showlink)
        except:
            if not quiet_on_error:
                print("No feed")



def print_nist_entry(url, nb_entry,keyword=None,keydate=None,severity=None,showlink=False,verbose=False,quiet_on_error=False):
    try:
        NewsFeed = JsonContent(url).content()
        NewsFeed_size = JsonContent(url).size()
    except AssertionError as error:
        print(error)
        print(url + " seems bad" )
    print ("There are " + str(NewsFeed_size) +" entries")
    print("******************************\n\n")
    r=nb_entry
    if nb_entry == 0:
        r = NewsFeed_size
    if (r >  NewsFeed_size):
        print("You want too much data more than real entries")
        r = NewsFeed_size
    for i in range(r):
        try:
            entry = NewsFeed['CVE_Items'][i]
            sev="unknown"
            try:
                sev=entry['impact']['baseMetricV3']['cvssV3']['baseSeverity']
            except:
                pass
            if severity is not None and sev.lower() != severity.lower():
                    continue
            if keyword is not None:
                if (entry['cve']['description']['description_data'][0]['value'].lower().find(keyword.lower()) == -1) and (entry['cve']['references']['reference_data'][0]['tags'][0].lower().find(keyword.lower()) == -1):
                    continue
            if keydate is not None:
                if (entry['publishedDate'].lower().find(keydate.lower()) == -1) :
                    continue
            print(entry['cve']['CVE_data_meta']['ID'])
            print(entry['publishedDate'])
            print("Severity: "+sev)
            print_nist_details(entry,verbose=verbose,showlink=showlink)
        except:
            if not quiet_on_error:
                print("No feed")


def print_entry(url, nb_entry,keyword=None,keydate=None,showlink=False,severity=None,verbose=False,quiet_on_error=False):
    if type(url)==str and ("cert" in url or "mitre" in url):
        print_cert_entry(url,nb_entry,keyword,keydate,severity=severity,showlink=showlink,verbose=verbose,quiet_on_error=quiet_on_error)
    else:
        print_nist_entry(url,nb_entry,keyword,keydate,severity=severity,showlink=showlink,verbose=verbose,quiet_on_error=quiet_on_error)

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    default_url="https://www.cert.ssi.gouv.fr/alerte/feed/"
    quiet=False
    parser = argparse.ArgumentParser()
    #parser.add_help("show entries from RSS feed link")
    parser.add_argument('-u','--url',dest='url', help="the rss link , default is "+default_url,
                    type=type_url, default=default_url )
    parser.add_argument('-f','--file',dest='file', help="a json/xml file to parse, (xml cert format; json nist format expected)  `",
                    type=str, default=None )
    parser.add_argument('-n',dest='entryval',default=0,help="entry number to show, 0 to see all ",
                    type=int)
    parser.add_argument('-k','--key',dest='kw',help="key word to look inside title of the feed ",
                    type=str)
    parser.add_argument('-d','--debug',action='store_true', required=False,help="Show keys in the rss fields")
    parser.add_argument('-q','--quiet',action='store_true', required=False,help="Do not show empty feed")
    parser.add_argument('--nist',action='store_true', required=False,default=False,help="Get nist infos")
    parser.add_argument('-v','--verbose',action='store_true', required=False,help="Display summary of elements")
    parser.add_argument('-l','--links',action='store_true', required=False,help="Display related link")
    parser.add_argument('-D','--date',dest='pubdate',help="date of info, for ssi gouv format is like 12 mars 2024, for nist yyyy-mm-dd ")
    parser.add_argument('-s','--severity',dest='severity', help="cve severity high/critical ",  type=str, default=None )
    args = parser.parse_args()

    source_link=args.url
    if args.nist:
        source_link=get_nist_json(date=args.pubdate)
    if args.file is not None:
        source_link=args.file
    if args.debug:
            print_entry_keys(source_link)
    
    print_entry(source_link,args.entryval,args.kw,args.pubdate,severity=args.severity,verbose=args.verbose,showlink=args.links,quiet_on_error=args.quiet)


