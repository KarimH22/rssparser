#!/bin/python3
# @author Karim HAROUAT
# CVE parser
from os import link
import string
import feedparser
import argparse
from argparse import RawTextHelpFormatter
import validators
import os
from lxml import etree, html
import json
import requests
import zipfile
import re
import tempfile as tmpfile
from datetime import datetime
import colorama as color
import time

####################################
########### TYPE
####################################
def type_url(strurl):
    if validators.url(strurl):
        return strurl
    else:
        raise argparse.ArgumentTypeError("Should be an real web link")

def type_cve(cveid):
    pattern= r'^CVE-(\d{4})-(\d{1,10})$'
    if bool(re.match(pattern,cveid)):
        return cveid
    else:
        raise argparse.ArgumentTypeError("Should be an string like CVE-xxxx-YYYYY where x and Y are digits")

def type_file(filename):
    if os.path.isfile(filename):
        return filename
    else:
        raise argparse.ArgumentTypeError("Should be an existing file")
    
def type_cve(cweid):
    pattern= r'^CWE-(\d{4})$'
    if bool(re.match(pattern,cweid)):
        return cweid
    else:
        raise argparse.ArgumentTypeError("Should be an string like CWE-xxxx where x are digits")

class CVEParameters:
    def __init__(self,nb_entry=0):
        self.nb_entry=nb_entry
        self.keyword=None
        self.published_date=None
        self.severity=None
        self.ignore_word=None
        self.exact_word=False
        self.product=None
        self.cve_id=None
        self.cwe_id=None
####################################
########### JsonContent class
####################################
class JsonContent:
    def __init__(self, filesource,tag='cve'):
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
# End class

####################################
########### COMMON
####################################

def print_debug(message):
    if (debug_mode):
        print(message)

def print_link(message):
    if showlink:
        print(message)
        print("==============================")

def print_severity(sev):
        severity_msg="Severity: "+sev
        if (sev.lower()=="high" or sev.lower() == "critical"):
                severity_msg=f"{color.Fore.RED}{severity_msg}{color.Style.RESET_ALL}"
        print(severity_msg)


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

def dump_json_entry(entry):
    if not dump_json:
        return
    for key in entry.keys():
        print(f"Key:{key}")
        for i in entry[key]:
            print(f"Value:{entry[key][i]}")

####################################
########### CERT
####################################
def print_cert_details(entry,keyword=None):
    if verbose:
        try:
            text =  html.fromstring(entry.summary).text_content()
            if keyword is not None:
                text=text.replace(keyword,f"{color.Fore.RED}{keyword}{color.Style.RESET_ALL}")
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
    print_link(link)

def print_cert_entry(url, cve_parameters):
    NewsFeed = feedparser.parse(url)
    NewsFeed_size=len(NewsFeed.entries)
    print ("There are " + str(NewsFeed_size) +" entries")
    print("******************************\n\n")
    local_nb_entry = NewsFeed_size
    if (cve_parameters.nb_entry >  NewsFeed_size):
        print("You ask for number of entries more than current one")
    if (cve_parameters.nb_entry != 0) : 
         local_nb_entry =  cve_parameters.nb_entry
    nb_found = 0
    for i in range(NewsFeed_size,0,-1):
        try:
            entry = NewsFeed.entries[i]
            if cve_parameters.ignore_word is not None:
                if (entry.title.lower().find(cve_parameters.ignore_word.lower()) != -1) or (entry.summary.lower().find(cve_parameters.ignore_word.lower()) != -1):
                    continue
            if cve_parameters.keyword is not None:
                if (entry.title.lower().find(cve_parameters.keyword.lower()) == -1) and (entry.summary.lower().find(cve_parameters.keyword.lower()) == -1):
                    continue
                if cve_parameters.exact_word and (not re.search(r'\b'+cve_parameters.keyword+r'\b',entry.title)) and (not re.search(r'\b'+cve_parameters.keyword+r'\b',entry.summary)) :
                    print(f"Look for {cve_parameters.keyword} : failed")
                    continue
            if cve_parameters.severity is not None:
                if (entry.title.lower().find(cve_parameters.severity.lower()) == -1) and (entry.summary.lower().find(cve_parameters.severity.lower()) == -1):
                    continue
            if cve_parameters.published_date is not None:
                if (type(cve_parameters.published_date) is str) and (entry.title.lower().find(cve_parameters.published_date.lower()) == -1) :
                    continue
            print(entry.title)
            print_cert_details(entry,cve_parameters.keyword)
        except:
            pass
        nb_found +=1
        if (nb_found == local_nb_entry):
            break

####################################
########### NIST
####################################

def get_nist_json(date=None):
    NIST_JSON_VERSION="2.0"
    cveperiod="recent"
    loop_range=[cveperiod]
    if date != None:
        if type(date) is str:
            year=str(date).split('-')[0]
            if year.isdigit() and int(year)>1000 :
                cveperiod=[int(year),int(year)]
        else:
            a=date[0].split('-')[0]
            b=date[1].split('-')[0]
            cveperiod=sorted([int(a),int(b)])
        loop_range=range(cveperiod[0],cveperiod[1]+1)
    compiled_data={'vulnerabilities':[]}
    for i in loop_range:
        url=nist_url+"/cve/"+NIST_JSON_VERSION+"/nvdcve-"+NIST_JSON_VERSION+"-"+str(i)+".json.zip"
        try:
            response=requests.get(url)
            local=tmpfile.NamedTemporaryFile('wb')
            local.write(response.content)
            data=zipfile.ZipFile(str(local.name))
            json_data=json.loads(data.read("nvdcve-"+NIST_JSON_VERSION+"-"+str(i)+".json"))
            compiled_data['vulnerabilities']+= json_data['vulnerabilities']
            data.close()
            local.close()
        except Exception as e:
            print(f"Try to get {url} but failed, error {str(e)}")
            exit(1)
    data_to_return= json.dumps(compiled_data).encode('utf-8')
    return data_to_return

def get_nist_id(entry):
    cve_id=""
    try:
        cve_id=entry['cve']['id']
    except:
        pass
    return cve_id

def get_nist_description(entry):
    desc ="No description"
    try:
        desc =  entry['cve']['descriptions'][0]['value']
    except:
        pass
    return desc

def get_nist_severity(entry):
    sev="unknown"
    for key in entry['cve']['metrics'].keys():
        if str(key).find("cvssMetricv3"):
            try:
                sev=entry['cve']['metrics'][key][0]['cvssData']['baseSeverity']
                break
            except:
                pass
    return sev

def get_nist_tags(entry):
    tags=""
    try:
        tags=entry['cve']['cveTags'].joined(",")
    except:
        pass
    return tags

def get_nist_affected_product(entry):
    products=""
    return products

def get_nist_vector_string(entry):
    vector_string=""
    for key in entry['cve']['metrics'].keys():
        if str(key).find("cvssMetricv3"):
            try:
                vector_string=entry['cve']['metrics'][key][0]['cvssData']['vectorString']
                break
            except:
                pass
    return vector_string

def get_nist_cwe(entry):
    cwe="NA"
    try:
        cwe =  entry['cve']['weaknesses'][0]['description'][0]['value']
    except:
        pass
    return cwe

def get_nist_links(entry):
    links = "Entry has no links attribute"
    nb_link=len(entry['cve']['references'])
    try:
        links = entry['cve']['references'][0]['url']
    except:
        pass
    try:
        for link_idx in range(1,nb_link):
            links += "\n" + entry['cve']['references'][link_idx]['url']
    except:
        print("Loop link failed")
        pass
    return links,nb_link

def get_nist_published_date(entry):
    return entry['cve']['published']

def print_nist_details(entry,keyword=None):
    if verbose:
        text =  get_nist_description(entry)
        if keyword is not None:
            text=text.replace(keyword,f"{color.Fore.RED}{keyword}{color.Style.RESET_ALL}")
        print(text)
        cwe=get_nist_cwe(entry)
        print(f"{color.Fore.YELLOW}CWE:{color.Style.RESET_ALL} {cwe}")
        vector_string=get_nist_vector_string(entry)
        print(f"{color.Fore.YELLOW}vectorString:{color.Style.RESET_ALL} {vector_string}")
    link,nb_link = get_nist_links(entry)
    print_link(f"{nb_link} link(s): \n{link}")

def print_nist_entry(url, cve_parameters):
    try:
        if (not os.path.exists(url)):
            url=get_nist_json(cve_parameters.published_date)
        NewsFeedObj = JsonContent(url,tag='vulnerabilities')
        NewsFeed = NewsFeedObj.content()
        NewsFeed_size = NewsFeedObj.size()
    except AssertionError as error:
        print(error)
        print(f"{url} : seems bad" )
    print (f"There are {NewsFeed_size} entries")
    print("******************************\n\n")
    local_nb_entry=NewsFeed_size
    if cve_parameters.nb_entry != 0 :
        local_nb_entry = cve_parameters.nb_entry
    if (cve_parameters.nb_entry > NewsFeed_size):
        print("You ask for number of entries more than current available")
    nb_found=0
    for i in range(NewsFeed_size):
        try:
            entry = NewsFeed['vulnerabilities'][i]
            sev=get_nist_severity(entry)
            description=get_nist_description(entry)
            tags=get_nist_tags(entry)
            pub_date=get_nist_published_date(entry)
            current_id=get_nist_id(entry)
            if cve_parameters.cve_id is not None and (current_id != cve_parameters.cve_id):
                    continue
            if cve_parameters.severity is not None and sev.lower() != cve_parameters.severity.lower():
                    continue
            if cve_parameters.ignore_word is not None:
                if (description.lower().find(cve_parameters.ignore_word.lower()) != -1):
                    continue
            if cve_parameters.keyword is not None:
                if (description.lower().find(cve_parameters.keyword.lower()) == -1) and (tags.lower().find(cve_parameters.keyword.lower()) == -1):
                    continue
                if cve_parameters.exact_word and (not re.search(r'\b'+cve_parameters.keyword+r'\b',description) ) and (not re.search(r'\b'+cve_parameters.keyword+r'\b',tags) ):
                    continue
            if cve_parameters.published_date is not None:
                if (type(cve_parameters.published_date) is str) and (pub_date.lower().find(cve_parameters.published_date.lower()) == -1) :
                    continue
                if (type(cve_parameters.published_date) is list):
                    try:
                        dateref0=time.strptime(cve_parameters.published_date[0], "%Y-%m-%d")
                        dateref1=time.strptime(cve_parameters.published_date[1], "%Y-%m-%d")
                        cvedate=time.strptime(pub_date.split("T")[0], "%Y-%m-%d")
                        if cvedate<dateref0 or cvedate>dateref1:
                            continue
                    except:
                        pass
            print(current_id)
            print(pub_date)
            print_severity(sev)
            print_nist_details(entry,cve_parameters.keyword)
            if cve_parameters.cve_id is not None:
                dump_json_entry(entry)
                break
            nb_found +=1
            if (nb_found == local_nb_entry):
                break
        except:
            pass


####################################
########### CVE.ORG
####################################

def get_cve_org_json(date=None, inputfile=None):
    current_date = datetime.today()
    current_year = current_date.year
    cveperiod = [current_year,current_year]
    if date != None:
        if type(date) is str:
            year=str(date).split('-')[0]
            if year.isdigit() and int(year)>1000 :
                cveperiod=[int(year),int(year)]
        if type(date) is list and len(date)>=2:
            year1=str(date[0]).split('-')[0]
            year2=str(date[1]).split('-')[0]
            if year1.isdigit() and int(year1)>1000 and year2.isdigit() and int(year2)>1000:
                cveperiod=sorted([int(year1),int(year2)])
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
        for name in data.namelist():
            if not name.endswith(".json"):
                continue
            name_splited=name.split("-")
            if len(name_splited) < 3:
                continue
            cve_year=name_splited[2]
            if ( int(cve_year)<cveperiod[0]) or ( int(cve_year)>cveperiod[1] ):
                continue
            data_to_return.insert(0,data.read(name))
        data.close()
        if (inputfile is None):
            local.close()
    except Exception as e:
        print(f"Try to fill  data_to_return but failed at {name}, error {str(e)}")
        exit(1)
    return data_to_return


def get_cve_published_date(entry):
    if 'cveMetadata' not in entry.keys():
        return ""
    else:
        return entry['cveMetadata']['datePublished']

def get_cve_description(entry):
    loc_entry=entry
    if 'containers' in entry.keys():
        loc_entry=entry['containers']
    text =""
    try:
        text =  loc_entry['cna']['descriptions'][0]['value']
    except:
        pass
    return text

def get_cve_severity(entry):
    sev="unknown"
    loc_entry=entry
    if 'containers' in entry.keys():
        loc_entry=entry['containers']
    try:
        sev=loc_entry['cna']['metrics'][0]['cvssV3_1']['baseSeverity']
    except:
        pass
    return sev

def get_cve_tags(entry):
    tags=""
    loc_entry=entry
    if 'containers' in entry.keys():
        loc_entry=entry['containers']
    try:
        tags=loc_entry['cve']['references']['reference_data'][0]['tags'][0]
    except:
        pass
    return tags

def get_cve_affected_product(entry):
    affected_product=""
    loc_entry=entry
    if 'containers' in entry.keys():
        loc_entry=entry['containers']
    try:
        affected_product=loc_entry['cna']['affected'][0]['product']
    except:
        pass
    return affected_product

def get_cve_vector_string(entry):
    vector_string=""
    loc_entry=entry
    if 'containers' in entry.keys():
        loc_entry=entry['containers']
    try:
        vector_string =  loc_entry['cna']['metrics'][0]['cvssV3_1']['vectorString']
    except:
        pass
    return vector_string

def get_cve_cwe(entry):
    cwe="NA"
    loc_entry=entry
    if 'containers' in entry.keys():
        loc_entry=entry['containers']
    try:
        cwe =  loc_entry['cna']['problemTypes'][0]['descriptions'][0]['cweId']
    except:
        pass
    return cwe

def get_cve_id(entry):
    cve_id=""
    if 'cveMetadata' not in entry.keys():
        return ""
    try:
       cve_id=entry['cveMetadata']['cveId']
    except:
        pass
    return cve_id

def get_cve_links(entry):
    loc_entry=entry
    if 'containers' in entry.keys():
        loc_entry=entry['containers']
    links = "Entry has no links attribute"
    nb_link=len(loc_entry['cna']['references'])
    try:
        links = loc_entry['cna']['references'][0]['url']
    except:
        pass
    try:
        for link_idx in range(1,nb_link):
            links += "\n" + loc_entry['cna']['references'][link_idx]['url']
    except:
        print("Loop link failed")
        pass
    return links,nb_link

def get_cve_first_link(entry):
    loc_entry=entry
    if 'containers' in entry.keys():
        loc_entry=entry['containers']
    link = "Entry has no links attribute"
    try:
        link = loc_entry['cna']['references'][0]['url']
    except:
        pass
    return link

def print_cve_org_details(entry,keyword=None,exact_word=False):
    if verbose:
        text =  get_cve_description(entry)
        if keyword is not None:
            text=text.replace(keyword,f"{color.Fore.RED}{keyword}{color.Style.RESET_ALL}")
        print(text)
        product=get_cve_affected_product(entry)
        print(f"{color.Fore.YELLOW}Product:{color.Style.RESET_ALL} {product}")
        cwe=get_cve_cwe(entry)
        print(f"{color.Fore.YELLOW}CWE:{color.Style.RESET_ALL} {cwe}")
        vector_string=get_cve_vector_string(entry)
        print(f"{color.Fore.YELLOW}vectorString:{color.Style.RESET_ALL} {vector_string}")
    link,nb_link=get_cve_links(entry)
    print_link(f"{nb_link} link(s): \n{link}")

def print_cve_org_entry(url, cve_parameters):
    try:
        data_content=get_cve_org_json(cve_parameters.published_date,url)
        data_size=len(data_content)
    except AssertionError as error:
        print(error)
        print(f"{url} : seems bad" )
    print (f"There are {data_size} entries")
    print("******************************\n\n")
    local_nb_entry=cve_parameters.nb_entry
    if cve_parameters.nb_entry == 0:
        local_nb_entry = data_size
    if (local_nb_entry >  data_size):
        print("You want too much data more than real entries")
        local_nb_entry = data_size
    nb_found=0
    published_date=cve_parameters.published_date
    for i in range(data_size):
        try:
            NewsFeedObj = JsonContent(filesource=data_content[i],tag='containers')
            NewsFeed = NewsFeedObj.content()
            #NewsFeed_size = NewsFeedObj.size()
            current_id=get_cve_id(NewsFeed)
            pub_date=get_cve_published_date(NewsFeed)
            entry = NewsFeed['containers']
            sev=get_cve_severity(entry)
            description=get_cve_description(entry)
            tags=get_cve_tags(entry)
            affected_product=get_cve_affected_product(entry)
            if cve_parameters.cve_id is not None and ( current_id != cve_parameters.cve_id):
                    continue
            if cve_parameters.severity is not None and sev.lower() != cve_parameters.severity.lower():
                    continue
            if cve_parameters.ignore_word is not None:
                if (description.lower().find(cve_parameters.ignore_word.lower()) != -1) or (get_cve_first_link(entry).lower().find(cve_parameters.ignore_word.lower()) != -1 ):
                    continue
            if cve_parameters.keyword is not None:
                if (description.lower().find(cve_parameters.keyword.lower()) == -1) and (tags.lower().find(cve_parameters.keyword.lower()) == -1):
                    continue
                if cve_parameters.exact_word and (not re.search(r'\b'+cve_parameters.keyword+r'\b',description) ) and (not re.search(r'\b'+cve_parameters.keyword+r'\b',tags) ):
                    continue
            if cve_parameters.product is not None:
                if (affected_product.lower().find(cve_parameters.product.lower()) == -1) :
                    continue
            if published_date is not None:
                if (type(published_date) is str) and (pub_date.lower().find(published_date.lower()) == -1) :
                    continue
                if (type(published_date) is list):
                    try:
                        dateref0=time.strptime(published_date[0], "%Y-%m-%d")
                        dateref1=time.strptime(published_date[1], "%Y-%m-%d")
                        cvedate=time.strptime(pub_date.split("T")[0],"%Y-%m-%d")
                        if cvedate<dateref0 or cvedate>dateref1:
                            continue
                    except:
                        pass
            print(current_id)
            print(pub_date)
            print_severity(sev)
            print_cve_org_details(entry,cve_parameters.keyword,cve_parameters.exact_word)
            if cve_parameters.cve_id is not None:
                dump_json_entry(entry)
                break
            nb_found+=1
            if (nb_found == local_nb_entry):
                break
        except:
            pass

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
showlink=False
verbose=False
debug_mode=False
dump_json=False
# Press the green button in the gutter to run the script.
if __name__ == '__main__':

    default_url=cert_ssi_url

    prog_description="Parse CVE from ssi.gouv.fr or nist site or cve.org\n\
        default is ssi.gouv.fr\n\
        to parse nist or cve.org data base see below"
    parser = argparse.ArgumentParser(description=prog_description,formatter_class=RawTextHelpFormatter)
    parser.add_argument('--nist',action='store_true', required=False,default=False,help="Get nist infos")
    parser.add_argument('--cve-org',action='store_true', required=False,default=False,help="Get cve.org infos took a large zip file take time")
    parser.add_argument('-f','--file',dest='file', help="a json/xml file to parse\n\
        cert.ssi.gouv.fr : xml format\n\
        if  nist json add option --nist\n\
        if cve.org zip file containing jsons, add --cve-org  ",
                    type=str, default=None )
    parser.add_argument('-n',dest='number_cve',default=0,help="entry number to show, 0 to see all ",
                    type=int)
    parser.add_argument('-D','--date',dest='published_date',help="to look for CVE on published date\n\
        date format for ssi.gouv.fr : 12 mars 2024\n\
        for nist,cve.org :  yyyy-mm-dd\n\
        for all you can set only the year: yyyy ")
    parser.add_argument('-b','--between',dest='pubdaterange',help="to look for CVE on published date\n\
        date format for ssi.gouv.fr : 12 mars 2024\n\
        for nist,cve.org :  yyyy-mm-dd--yyyy-mm-dd\n\
        for all you can set only the year: yyyy;yyyy ")
    parser.add_argument('-s','--severity',dest='severity', help=" for cert ssi : critique|haute|medium\
        \n for nist : high|critical \
        \n for cve.org : low|medium|high|critical ",  type=str, default=None )
    parser.add_argument('-k','--key',dest='kw',help="key word to look inside title of the feed,\n\
        for many words use quotes, e.g -k \"sql injection\" ", type=str)
    parser.add_argument('-p','--product',dest='product',help="product affected", type=str)
    parser.add_argument('-v','--verbose',action='store_true', required=False,help="Display summary of elements")
    parser.add_argument('-l','--links',action='store_true', required=False,help="Display related link")

    parser.add_argument('--ignore',dest='ignorew',help="cve to ignore with given key word",
                    type=str)
    parser.add_argument('--get-cve-org-data',action='store_true', required=False,default=False,help="Get cve zip source localy and exit")
    parser.add_argument('-d','--debug',action='store_true', required=False,help="Show keys in the rss fields")
    parser.add_argument('--exact-key',action='store_true', required=False,help="exact key")
    parser.add_argument('-i','--id',dest='cve_id', help=" exact cve id",  type=type_cve, default=None )
    parser.add_argument('--dump',action='store_true', required=False,help="Dump json all cve id")
    args = parser.parse_args()

    if args.get_cve_org_data:
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
    if args.verbose:
        verbose=True
        showlink=True
    if args.links:
        showlink=True
    if args.dump:
        dump_json=True
    if args.cve_id is not None and args.published_date is None:
        args.published_date=args.cve_id.split("-")[1]
        if args.nist and (args.cve_id.split("-")[1] == str(datetime.now().year)):
            args.published_date=None
    if args.pubdaterange is not None:
        daterange=args.pubdaterange.split("--")
        if len(daterange)>=2:
            daterange=sorted(daterange)
            if len(daterange[0].split("-"))<=1:
                daterange[0]=daterange[0]+"-01-01"
            if len(daterange[1].split("-"))<=1:
                daterange[1]=daterange[1]+"-12-31"
            args.published_date=[daterange[0],daterange[1]]
    
    my_cve_parameters=CVEParameters(args.number_cve)
    my_cve_parameters.keyword=args.kw
    my_cve_parameters.published_date=args.published_date
    my_cve_parameters.severity=args.severity
    my_cve_parameters.ignore_word=args.ignorew
    my_cve_parameters.exact_word=args.exact_key
    my_cve_parameters.product=args.product
    my_cve_parameters.cve_id=args.cve_id

    cve_format_funs[source]['fun'](source_link,my_cve_parameters)
