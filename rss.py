#!/bin/python3
# @author Karim HAROUAT
# CVE parser
from os import link
import string
import feedparser
import argparse
import validators
import os
from lxml import etree, html
import json
import requests
import zipfile
import tempfile as tmpfile
from datetime import datetime


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
    def __init__(self, filesource,tag='CVE_Items'):
        self.json_content = None
        self.main_tag=tag
        if (os.path.isfile(filesource)):
            if (filesource.endswith(".json")):
                content_file = open(filesource,'r')
                self.json_content = json.load(content_file)
                content_file.close()
            if (filesource.endswith(".zip")):
                data=zipfile.ZipFile(filesource)
                name_list=data.namelist()
                content_zip=data.read(name_list[0])
                data.close()
                self.json_content = json.loads(content_zip)
        else:
            self.json_content = json.loads(filesource)

    def content(self):
        return self.json_content
    def size(self):
        if self.json_content == "" or self.json_content == {}:
            return 0
        return len(self.json_content[self.main_tag])


def get_nist_json(date=None):
    cveperiod="recent"
    if date != None:
        year=str(date).split('-')[0]
        if year.isdigit() and int(year)>1000 :
            cveperiod=year
    url=nist_url+"/cve/1.1/nvdcve-1.1-"+cveperiod+".json.zip"
    try:
        response=requests.get(url)
        local=tmpfile.NamedTemporaryFile('wb')
        local.write(response.content)
        data=zipfile.ZipFile(str(local.name))
        data_to_return=data.read("nvdcve-1.1-"+cveperiod+".json")
        data.close()
        local.close()
        return data_to_return
    except Exception as e:
        print(f"Try to get {url} but failed, error {str(e)}")
        exit(1)

def get_cve_org_json(date=None, inputfile=None):
    current_date = datetime.today()
    current_year = current_date.year
    current_date_suffix = current_date.strftime("%Y_%m_%d_%H_%M_%S")
    cveperiod = current_year
    if date != None:
        year=str(date).split('-')[0]
        if year.isdigit() and int(year)>1000 :
            cveperiod=year
    try:
        filename=""
        if (not os.path.isfile(inputfile)):
            response=requests.get(cve_org_zip_url)
            local=tmpfile.NamedTemporaryFile('wb')    
            local.write(response.content)
            filename=str(local.name)
        else:
            if(inputfile.endswith("json")):
                f=open(inputfile,'r')
                data_to_return=f.read()
                f.close()
                return data_to_return
            filename=os.path.abspath(inputfile)
        data=zipfile.ZipFile(filename)
    except Exception as e:
        print(f"Try to get {filename} but failed, error {str(e)}")
        exit(1)
    try:
        data_to_return=[]
        print(cveperiod)
        for name in data.namelist():
            if (  name.find("CVE-"+str(cveperiod)) == -1 ) or not name.endswith(".json"):
                continue
            data_to_return.append(data.read(name))
        data.close()
        if (inputfile is None):
            local.close()
    except Exception as e:
        print(f"Try to fill  data_to_return but failed at {name}, error {str(e)}")
        exit(1)
    return data_to_return


def print_entry_keys(url):
    try:
        if type(url) != str:
            print("Error not a string :"+url )
            return
        if url == cert_ssi_url:
            print("Reading cert xml file")
            NewsFeed = feedparser.parse(url)
            entry = NewsFeed.entries[0]
            print(entry)
        if url == nist_url:
            print("Reading nist json file")
            NewsFeed = JsonContent(get_nist_json()).content()
            first=NewsFeed['CVE_Items'][0]['cve']['CVE_data_meta']['ID']
            print(first)
        if (url == cve_org_url):
            print("Reading org cve json file")
            NewsFeed = JsonContent(get_cve_org_json(),'containers').content()
            first=NewsFeed["cveMetadata"][0]['cveId']
            print(first)
    except Exception as e:
        print(f"Link is bad or not rss feed so that no keys attribute : {e}")

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
        print("Link error")
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
        print("Link error")
    if verbose or showlink:
        print(link)
    if verbose or showlink:
        print("==============================")

def print_cve_org_details(entry,showlink=False,verbose=False):
    if verbose:
        try:
            text =  entry['cna']['descriptions'][0]['value']
        except:
            text = "Nothing found"
        print(text)

    nb_link=len(entry['cna']['references'])
    try:
        link = entry['cna']['references'][0]['url']
    except:
        link = "Entry has no links attribute"
    try:
        for link_idx in range(1,nb_link):
            link += "\n" + entry['cna']['references'][link_idx]['url']
    except:
        print("Loop link failed")
        pass
    if verbose or showlink:
        print(f"{nb_link} links: \n{link}")
    if verbose or showlink:
        print("==============================")

def print_cert_entry(url, nb_entry,keyword=None,keydate=None,severity=None,showlink=False,verbose=False,quiet_on_error=False,ignore_word=None):
    NewsFeed = feedparser.parse(url)
    NewsFeed_size=len(NewsFeed.entries)
    print ("There are " + str(NewsFeed_size) +" entries")
    print("******************************\n\n")
    start_range = NewsFeed_size
    end_range = 0
    if (start_range > 1):
        start_range = start_range - 1
    if (nb_entry >  NewsFeed_size):
        print("You ask for number of entries more than current one")
        end_range = 0
    else:
        if (nb_entry != 0) : 
            end_range =  NewsFeed_size - nb_entry
        if(end_range > 1):
            end_range = end_range - 1
    for i in range(start_range,end_range,-1):
        try:
            entry = NewsFeed.entries[i]
            if ignore_word is not None:
                if (entry.title.lower().find(ignore_word.lower()) != -1) or (entry.summary.lower().find(ignore_word.lower()) != -1):
                    continue
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



def print_nist_entry(url, nb_entry,keyword=None,keydate=None,severity=None,showlink=False,verbose=False,quiet_on_error=False,ignore_word=None):
    try:
        if (not os.path.exists(url)):
            url=get_nist_json(keydate)
        NewsFeedObj = JsonContent(url)
        NewsFeed = NewsFeedObj.content()
        NewsFeed_size = NewsFeedObj.size()
    except AssertionError as error:
        print(error)
        print(f"{url} : seems bad" )
    print (f"There are {NewsFeed_size} entries")
    print("******************************\n\n")
    r=nb_entry
    if nb_entry == 0:
        r = NewsFeed_size
    if (r >  NewsFeed_size):
        print("You ask for number of entries more than current available")
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
            if ignore_word is not None:
                if (entry['cve']['description']['description_data'][0]['value'].lower().find(ignore_word.lower()) != -1):
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




def print_cve_org_entry(url, nb_entry,keyword=None,keydate=None,severity=None,showlink=False,verbose=False,quiet_on_error=False,ignore_word=None):
    try:
        data_content=get_cve_org_json(keydate,url)
        data_size=len(data_content)
    except AssertionError as error:
        print(error)
        print(f"{url} : seems bad" )
    print (f"There are {data_size} entries")
    print("******************************\n\n")
    r=nb_entry
    if nb_entry == 0:
        r = data_size
    if (r >  data_size):
        print("You want too much data more than real entries")
        r = data_size
    for i in range(r):
        try:
            NewsFeedObj = JsonContent(filesource=data_content[i],tag='containers')
            NewsFeed = NewsFeedObj.content()
            NewsFeed_size = NewsFeedObj.size()
            entry = NewsFeed['containers']
            sev="unknown"
            try:
                sev=entry['cna']['metrics'][0]['cvssV3_1']['baseSeverity']
            except:
                pass
            try:
                description=entry['cna']['descriptions'][0]['value']
            except:
                description=""
            if severity is not None and sev.lower() != severity.lower():
                    continue
            if ignore_word is not None:
                if (description.lower().find(ignore_word.lower()) != -1):
                    continue
            if keyword is not None:
                if (description.lower().find(keyword.lower()) == -1) and (entry['cve']['references']['reference_data'][0]['tags'][0].lower().find(keyword.lower()) == -1):
                    continue
            if keydate is not None:
                if (NewsFeed['cveMetadata']['datePublished'].lower().find(keydate.lower()) == -1) :
                    continue
            print(NewsFeed['cveMetadata']['cveId'])
            print(NewsFeed['cveMetadata']['datePublished'])
            print("Severity: "+sev)
            print_cve_org_details(entry,verbose=verbose,showlink=showlink)
        except:
            if not quiet_on_error:
                print("No feed")

def get_main_zip_cve_org():
    response=requests.get(cve_org_zip_url)
    file_name="cvelistV5-main.zip"
    local_file=open(file_name,'wb')
    if local_file:
        local_file.write(response.content)
        print(f"Get last main cve org in {file_name}")
        print(f"You can  call now : rss.py --cve-org -f {file_name} [options]")

#########################################################################
#################### MAIN
cert_ssi_url="https://www.cert.ssi.gouv.fr/alerte/feed/"
cve_org_url="https://www.cve.org"
cve_org_zip_url="https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"
nist_url="https://nvd.nist.gov/feeds/json"
cve_format_funs={
    "cert_ssi":{
        "url":cert_ssi_url,
        "fun":print_cert_entry,
    },
    "nist":{
        "url":nist_url,
        "fun":print_nist_entry,
    },
    "cve_org":{
        "url":cve_org_url,
        "fun":print_cve_org_entry,
    }
}

# Press the green button in the gutter to run the script.
if __name__ == '__main__':

    default_url=cert_ssi_url
    quiet=False
    parser = argparse.ArgumentParser()
    #parser.add_help("show entries from RSS feed link")
    parser.add_argument('-f','--file',dest='file', help="a json/xml file to parse, (xml cert format; if  nist json add option --nist)  `",
                    type=str, default=None )
    parser.add_argument('-n',dest='entryval',default=0,help="entry number to show, 0 to see all ",
                    type=int)
    parser.add_argument('-k','--key',dest='kw',help="key word to look inside title of the feed ",
                    type=str)
    parser.add_argument('-d','--debug',action='store_true', required=False,help="Show keys in the rss fields")
    parser.add_argument('-q','--quiet',action='store_true', required=False,help="Do not show empty feed")
    parser.add_argument('--nist',action='store_true', required=False,default=False,help="Get nist infos")
    parser.add_argument('--cve-org',action='store_true', required=False,default=False,help="Get cve.org infos took a large zip file take time")
    parser.add_argument('-v','--verbose',action='store_true', required=False,help="Display summary of elements")
    parser.add_argument('-l','--links',action='store_true', required=False,help="Display related link")
    parser.add_argument('-D','--date',dest='pubdate',help="date of info, for ssi gouv format is like 12 mars 2024, for nist yyyy-mm-dd ")
    parser.add_argument('-s','--severity',dest='severity', help="cve severity \n for cert ssi : critique|haute|medium\
                        \n for nist : high|critical \
                        \n for cve.org : low|medium|high|critical ",  type=str, default=None )
    parser.add_argument('--ignore',dest='ignorew',help="cve to ignore with given word ",
                    type=str)
    parser.add_argument('--get-cve-data',action='store_true', required=False,default=False,help="Get cve zip source localy to launch after with option -f")
    args = parser.parse_args()

    if args.get_cve_data:
        get_main_zip_cve_org()
        exit(0)
    source="cert_ssi"
    if args.nist:
        source="nist"
    if args.cve_org and not args.nist:
        source="cve_org"
    source_link=cve_format_funs[source]["url"]

    if args.file is not None:
        source_link=args.file
    if args.debug:
            print_entry_keys(source_link)

    cve_format_funs[source]['fun'](source_link,args.entryval,args.kw,args.pubdate,severity=args.severity,verbose=args.verbose,showlink=args.links,quiet_on_error=args.quiet,ignore_word=args.ignorew)
