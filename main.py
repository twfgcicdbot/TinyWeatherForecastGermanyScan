"""

**title**: TinyWeatherForecastGermany - exodusprivacy local apk scan

**author**: Jean-Luc Tibaux (https://gitlab.com/eUgEntOptIc44)

**license**: GPLv3

**since**: August 2021

## Disclaimer
No warranty or guarantee of any kind provided. Use at your own risk.
Not meant to be used in commercial or in general critical/productive environments at all.

"""

from datetime import datetime
from pathlib import Path
from pprint import pprint
import hashlib
import logging
import json
import random
import shutil
import sys
import time

from bs4 import BeautifulSoup
import requests

from exodus_core.analysis.static_analysis import StaticAnalysis
from exodus_core.analysis.apk_signature import ApkSignature

try:
    logging.basicConfig(format=u'%(asctime)-s %(levelname)s [%(name)s]: %(message)s', level=logging.DEBUG)
except Exception as e:
    logging.error("while logger init! -> error: "+str(e))

workingDir = Path("")

# source of user agent data -> https://github.com/tamimibrahim17/List-of-user-agents/blob/master/Chrome.txt
UserAgents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36","Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2919.83 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2866.71 Safari/537.36","Mozilla/5.0 (X11; Ubuntu; Linux i686 on x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2820.59 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2762.73 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2656.18 Safari/537.36","Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/44.0.2403.155 Safari/537.36","Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36","Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36","Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36","Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2226.0 Safari/537.36","Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36"]

random.shuffle(UserAgents)

UserAgent = str(random.choice(UserAgents))

logging.debug("querying data as '"+UserAgent+"' ")

headers = {
    "User-Agent": UserAgent,
    "DNT":"1"
}

searchCodebergReq = requests.get("https://codeberg.org/api/v1/repos/Starfish/TinyWeatherForecastGermany/releases?limit=1", headers=headers)

try:
    searchResultCodebergJson = json.loads(str(searchCodebergReq.text))
    #pprint(searchResultCodebergJson)
    logging.debug("fetched Codeberg data")
except Exception as e:
    logging.error("codeberg api request failed! -> error: "+str(e))

if len(searchResultCodebergJson) == 1 and searchResultCodebergJson != None:
    twfgJson = searchResultCodebergJson[0]
    
    pprint(twfgJson)
    
    if twfgJson == None:
        logging.error("content of key 'results' in codeberg json response is 'None' ")

        try:
            pprint(str(searchCodebergReq.headers))
            pprint(str(searchCodebergReq.text))
        except Exception as e:
            logging.error("failed to print request raw data to console! -> error: "+str(e))

        sys.exit(1)
    
    apkUrl = str(twfgJson["assets"][0]["browser_download_url"])
    filename = str(twfgJson["assets"][0]["name"])

    logging.debug("downloading '"+str(filename)+"' from -> "+str(apkUrl)+" ... ")
    
    response = requests.get(apkUrl, stream=True, headers=headers)
    with open(filename, 'wb') as out_file:
        shutil.copyfileobj(response.raw, out_file)
    del response

    logging.debug("file name: " + filename)

    sha256_hash = hashlib.sha256()
    with open(filename,"rb") as f: # source: https://www.quickprogrammingtips.com/python/how-to-calculate-sha256-hash-of-a-file-in-python.html
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
        sha256_hash = str(sha256_hash.hexdigest())

    sha256_hash = str(sha256_hash)
    logging.debug("file hash: " + sha256_hash)
    
    try:
        apkFiles = list(workingDir.glob('*.apk'))
        pprint(apkFiles)
        
        if len(apkFiles) > 0:
            for apkFileTemp in apkFiles:
                try:
                    logging.debug("apk file '"+str(apkFileTemp.absolute())+"' -> size: "+str(apkFileTemp.stat().st_size))
                    
                    resultDict = {}
                    
                    analysisTemp = StaticAnalysis(str(apkFileTemp.absolute())) # init ExodusPrivacy StaticAnalysis for 'apkFileTemp'
                    
                    try:
                        analysisTemp.print_apk_infos()
                    except Exception as e:
                        logging.error("printing of 'apk_infos' to console failed! -> error: "+str(e))
                    
                    # --- start of apk_infos ---
                    try:
                        permissions = analysisTemp.get_permissions()
                        if permissions != None:
                            logging.debug("static analysis returned "+str(len(permissions))+" permission(s) ")
                            resultDict["permissions"] = []
                            for permissionTemp in permissions:
                                try:
                                    resultDict["permissions"].append(str(permissionTemp))
                                except Exception as e:
                                    logging.error("saving of permission '"+str(permissionTemp)+"' of '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                        else:
                            logging.error("parsing of 'permissions' for apk '"+str(apkFileTemp)+"' failed! -> error: result is None!")    
                    except Exception as e:
                        logging.error("parsing of 'permissions' for apk '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                        
                    try:
                        libraries = analysisTemp.get_libraries()
                        if libraries != None:
                            logging.debug("static analysis returned "+str(len(libraries))+" libraries ")
                            resultDict["libraries"] = []
                            for libraryTemp in libraries:
                                try:
                                    resultDict["libraries"].append(str(libraryTemp))
                                except Exception as e:
                                    logging.error("saving of library '"+str(libraryTemp)+"' of '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                        else:
                            logging.error("parsing of 'libraries' for apk '"+str(apkFileTemp)+"' failed! -> error: result is None!")    
                    except Exception as e:
                        logging.error("parsing of 'libraries' for apk '"+str(apkFileTemp)+"' failed! -> error: "+str(e))

                    try:
                        certificates = analysisTemp.get_certificates()
                        if certificates != None:
                            logging.debug("static analysis returned "+str(len(certificates))+" certificate(s) ")
                            resultDict["certificates"] = []
                            for certificateTemp in certificates:
                                try:
                                    resultDict["certificates"].append(str(certificateTemp))
                                except Exception as e:
                                    logging.error("saving of certificate '"+str(certificateTemp)+"' of '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                        else:
                            logging.error("parsing of 'certificates' for apk '"+str(apkFileTemp)+"' failed! -> error: result is None!")    
                    except Exception as e:
                        logging.error("parsing of 'certificates' for apk '"+str(apkFileTemp)+"' failed! -> error: "+str(e))

                    try:
                        apkSum = str(analysisTemp.get_sha256())
                        if apkSum != "None":
                            logging.debug("static analysis returned apk hash (sha256): "+str(apkSum))
                            resultDict["hash_sha256"] = apkSum
                        else:
                            logging.error("parsing of 'get_sha256()' for apk '"+str(apkFileTemp)+"' failed! -> error: result is None!")    
                    except Exception as e:
                        logging.error("parsing of 'get_sha256()' for apk '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                    
                    try:
                        apkVersion = str(analysisTemp.get_version())
                        if apkVersion != "None":
                            logging.debug("static analysis returned apk version: "+str(apkVersion))
                            resultDict["version"] = apkVersion
                        else:
                            logging.error("parsing of 'get_version()' for apk '"+str(apkFileTemp)+"' failed! -> error: result is None!")    
                    except Exception as e:
                        logging.error("parsing of 'get_version()' for apk '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                    
                    try:
                        apkVersionCode = analysisTemp.get_version_code()
                        if apkVersionCode != None:
                            logging.debug("static analysis returned apk version code: "+str(apkVersionCode))
                            resultDict["version_code"] = apkVersionCode
                        else:
                            logging.error("parsing of 'get_version_code()' for apk '"+str(apkFileTemp)+"' failed! -> error: result is None!")    
                    except Exception as e:
                        logging.error("parsing of 'get_version_code()' for apk '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                    
                    try:
                        apkUID = str(analysisTemp.get_application_universal_id())
                        if apkUID != "None":
                            logging.debug("static analysis returned apk UID: "+str(apkUID))
                            resultDict["UID"] = apkUID
                        else:
                            logging.error("parsing of 'get_application_universal_id()' (UID) for apk '"+str(apkFileTemp)+"' failed! -> error: result is None!")    
                    except Exception as e:
                        logging.error("parsing of 'get_application_universal_id()' (UID) for apk '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                    
                    try:
                        apkName = str(analysisTemp.get_app_name())
                        if apkName != "None":
                            logging.debug("static analysis returned app name: "+str(apkName))
                            resultDict["name"] = apkName
                        else:
                            logging.error("parsing of 'get_app_name()' for apk '"+str(apkFileTemp)+"' failed! -> error: result is None!")    
                    except Exception as e:
                        logging.error("parsing of 'get_app_name()' for apk '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                    
                    try:
                        apkPackage = str(analysisTemp.get_package())
                        if apkPackage != "None":
                            logging.debug("static analysis returned app package: "+str(apkPackage))
                            resultDict["package"] = apkPackage
                        else:
                            logging.error("parsing of 'get_package()' for apk '"+str(apkFileTemp)+"' failed! -> error: result is None!")    
                    except Exception as e:
                        logging.error("parsing of 'get_package()' for apk '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                    
                    # --- end of apk_infos ---
                    
                    # --- start of embedded_trackers ---
                    
                    try:
                        analysisTemp.print_embedded_trackers()
                    except Exception as e:
                        logging.error("printing of 'embedded_trackers' to console failed! -> error: "+str(e))                    
                    
                    try:
                        embeddedTrackers = analysisTemp.detect_trackers()
                        if embeddedTrackers != None:
                            logging.debug("static analysis returned the following trackers: "+str(embeddedTrackers))
                            resultDict["trackers"] = embeddedTrackers
                        else:
                            logging.error("parsing of 'detect_trackers()' for apk '"+str(apkFileTemp)+"' failed! -> error: result is None!")    
                    except Exception as e:
                        logging.error("parsing of 'detect_trackers()' for apk '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                    
                    # --- end of embedded_trackers ---

                    # --- start of embedded_classes ---
                    
                    try:
                        embeddedClasses = analysisTemp.get_embedded_classes()
                        if embeddedClasses != None:
                            logging.debug("static analysis returned the following classes: "+str(embeddedClasses))
                            resultDict["classes"] = embeddedClasses
                        else:
                            logging.error("parsing of 'get_embedded_classes()' for apk '"+str(apkFileTemp)+"' failed! -> error: result is None!")    
                    except Exception as e:
                        logging.error("parsing of 'get_embedded_classes()' for apk '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                    
                    # --- end of embedded_classes ---

                    try:
                        #pprint(resultDict)                        
                        with open(str(Path(workingDir / "analysis-result.json").absolute()), "w+", encoding="utf-8") as fh:
                            fh.write(str(json.dumps(resultDict, indent=4)))
                    except Exception as e:
                        logging.error("while trying to save analysis result -> error: "+str(e))
                    
                    try:
                        #pprint(analysisTemp.signatures[0])                        
                        with open(str(Path(workingDir / "tracker-signatures.json").absolute()), "w+", encoding="utf-8") as fh:
                            fh.write(str(json.dumps(analysisTemp.signatures, indent=4)))
                    except Exception as e:
                        logging.error("while trying to save tracker signatures -> error: "+str(e))

                except Exception as e:
                    logging.error("while processing '"+str(apkFileTemp)+"' -> error: "+str(e))
    except Exception as e:
        logging.error(""+str(e))

else:
    logging.error("content of codeberg json response is invalid! ")

    try:
        pprint(str(searchCodebergReq.headers))
        pprint(str(searchCodebergReq.text))
    except Exception as e:
        logging.error("failed to print request raw data to console! -> error: "+str(e))

    sys.exit(1)

print("done")
