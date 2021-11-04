"""
ATTENTION: status -> WIP! -> development in early stage

license: GPLv3

author: Jean-Luc Tibaux

DISCLAIMER:
use only at your own risk. your mileage might vary.
no warranty or guarantee of any kind provided.


"""

from pathlib import Path
from pprint import pprint
import json
import regex
import logging
import subprocess
import sys

from ripgrepy import Ripgrepy
# The Ripgrepy class takes two arguments. The regex to search for and the folder path to search in
# docs: https://ripgrepy.readthedocs.io/en/latest/

workingDir = Path("TinyWeatherForecastGermanyScan")
workingDir.mkdir(parents=True, exist_ok=True) # create directory if not exists

try:
    logging.basicConfig(format=u'%(asctime)-s %(levelname)s [%(name)s]: %(message)s',
        level=logging.DEBUG,
        handlers=[
            logging.FileHandler(str(Path(workingDir / "debug.log").absolute()), encoding="utf-8"),
            logging.StreamHandler()
    ])
except Exception as e:
    logging.error("while logger init! -> error: "+str(e))

apkFiles = list(workingDir.glob('*.apk'))
pprint(apkFiles)

if len(apkFiles) == 0:
    logging.error("failed to find apk file -> aborting execution")
    sys.exit(1)

logging.debug("found apk file(s):")
apkFilePath = apkFiles[0]

logging.debug("reverse engineering '"+str(apkFilePath)+"' using apktool ... ")
# reverse engineering apk -> output: smali code
subprocess.run(["apktool","d",str(apkFilePath),"-o","TinyWeatherForecastGermanyApk","-f"])

logging.debug("saved extracted contents of '"+str(apkFilePath)+"' to 'TinyWeatherForecastGermanyApk/' ")

rg = Ripgrepy('(?im)http(s)*://', 'TinyWeatherForecastGermanyApk/smali')
http_matches_list = rg.H().n().json().run().as_dict

logging.debug("found "+str(len(http_matches_list))+" matches for '(?im)http(s)*://' in smali code ")

#with open("temp.json","w+",encoding="utf-8") as fh:
#    fh.write(str(json.dumps(http_matches_list, indent=4)))

http_cleaned_matches = {}

for http_match_dict in http_matches_list:
    try:
        url_temp = str(regex.findall(r'(?im)\b((?:[a-z][\w-]+:(?:\/{1,3}|[a-z0-9%])|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}\/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?«»“”‘’]))', str(http_match_dict["data"]["lines"]["text"]).strip())[0][0]).strip()
        if url_temp not in http_cleaned_matches:
            http_cleaned_matches[url_temp] = 1
        else:
            http_cleaned_matches[url_temp] += 1
    except Exception as e:
        logging.error("failed to parse http url match dict -> error: "+str(e))

pprint(http_cleaned_matches)

#with open("temp2.json","w+",encoding="utf-8") as fh:
#    fh.write(str(json.dumps(http_cleaned_matches, indent=4)))

# --------------- email ----------------------

rg = Ripgrepy('(?im)^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$', 'TinyWeatherForecastGermanyApk/smali')
email_matches_list = rg.H().n().json().run().as_dict

logging.debug("found "+str(len(email_matches_list))+" matches for email pattern in smali code ")

#with open("temp.json","w+",encoding="utf-8") as fh:
#    fh.write(str(json.dumps(email_matches_list, indent=4)))

email_cleaned_matches = {}

for email_match_dict in email_matches_list:
    try:
        email_temp = str(email_match_dict["data"]["lines"]["text"]).strip()
        if email_temp not in email_cleaned_matches:
            email_cleaned_matches[email_temp] = 1
        else:
            email_cleaned_matches[email_temp] += 1
    except Exception as e:
        logging.error("failed to parse email match dict -> error: "+str(e))

pprint(email_cleaned_matches)

#with open("temp2.json","w+",encoding="utf-8") as fh:
#    fh.write(str(json.dumps(email_cleaned_matches, indent=4)))

# --------------- ipaddress ----------------------
"""
# IPv4
rg = Ripgrepy('(?im)\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}', 'TinyWeatherForecastGermanyApk/smali')
ipaddress_matches_list = rg.H().n().json().run().as_dict

# IPv6
rg = Ripgrepy('(?im)(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))', 'TinyWeatherForecastGermanyApk/smali')
ipaddress_matches_list2 = rg.H().n().json().run().as_dict
 
ipaddress_matches_list += ipaddress_matches_list2

logging.debug("found "+str(len(ipaddress_matches_list))+" matches for the ipaddress patterns in smali code ")

#with open("temp.json","w+",encoding="utf-8") as fh:
#    fh.write(str(json.dumps(ipaddress_matches_list, indent=4)))
"""
ipaddress_cleaned_matches = {}
"""
for ipaddress_match_dict in ipaddress_matches_list:
    try:
        ipaddress_temp = str(ipaddress_match_dict["data"]["lines"]["text"]).strip()
        if ipaddress_temp not in ipaddress_cleaned_matches:
            ipaddress_cleaned_matches[ipaddress_temp] = 1
        else:
            ipaddress_cleaned_matches[ipaddress_temp] += 1
    except Exception as e:
        logging.error("failed to parse ipaddress match dict -> error: "+str(e))

pprint(ipaddress_cleaned_matches)

#with open("temp2.json","w+",encoding="utf-8") as fh:
#    fh.write(str(json.dumps(ipaddress_cleaned_matches, indent=4)))
"""

with open("TinyWeatherForecastGermanyScan/rg-pattern-matches.json","w+",encoding="utf-8") as fh:
    fh.write(str(json.dumps({"http":http_cleaned_matches,"emails":email_cleaned_matches, "ipaddress":ipaddress_cleaned_matches}, indent=4)))

print("done")