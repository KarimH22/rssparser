# Summary
- [Content](#content)
- [Install](#install)
- [Tips](#tips)

# Content
This is a python rss parser script to read Nist, Mitre (cve.org) and Cert feeds (json and xml file ).

The repository contains:
- rss.py : the parser
- install_required_pkg.sh :  install required package on linux 
- rss_completion.sh : shell script to get auto completion

# Install

To install it copy rss.py into `/usr/bin` or `/usr/local/bin` , be sure to have this path inside your PATH env.

# Tips 
For cve.org, tips:
 - get locally the last main.zip 
    ```bash
    rss.py --get-cve-org-data
    ```
 - parse the zip file 
    ```bash
    rss.py --cve-org -f cvelistV5-main.zip [opts]
    ```