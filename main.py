"""

@title TinyWeatherForecastGermany - exodusprivacy apk scan

@author Jean-Luc Tibaux (https://gitlab.com/eUgEntOptIc44)

@license GPLv3

@since August 2021

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
    print("ERROR: while logger init! -> error: "+str(e))

workingDir = Path("")

# source of user agent data -> https://github.com/tamimibrahim17/List-of-user-agents/blob/master/Chrome.txt
UserAgents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36","Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2919.83 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2866.71 Safari/537.36","Mozilla/5.0 (X11; Ubuntu; Linux i686 on x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2820.59 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2762.73 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2656.18 Safari/537.36","Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/44.0.2403.155 Safari/537.36","Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36","Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36","Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36","Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2226.0 Safari/537.36","Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36"]

random.shuffle(UserAgents)

UserAgent = str(random.choice(UserAgents))

print("DEBUG: querying data as '"+UserAgent+"' ")

headers = {
    "User-Agent": UserAgent,
    "DNT":"1"
}

searchCodebergReq = requests.get("https://codeberg.org/api/v1/repos/Starfish/TinyWeatherForecastGermany/releases?limit=1", headers=headers)

try:
    searchResultCodebergJson = json.loads(str(searchCodebergReq.text))
    #pprint(searchResultCodebergJson)
    print("DEBUG: fetched Codeberg data")
except Exception as e:
    print("ERROR: codeberg api request failed! -> error: "+str(e))

if len(searchResultCodebergJson) == 1 and searchResultCodebergJson != None:
    twfgJson = searchResultCodebergJson[0]
    
    pprint(twfgJson)
    
    if twfgJson == None:
        print("ERROR: content of key 'results' in codeberg json response is 'None' ")

        try:
            pprint(str(searchCodebergReq.headers))
            pprint(str(searchCodebergReq.text))
        except Exception as e:
            print("ERROR: failed to print request raw data to console! -> error: "+str(e))

        sys.exit(1)
    
    apkUrl = str(twfgJson["assets"][0]["browser_download_url"])
    filename = str(twfgJson["assets"][0]["name"])

    print("DEBUG: downloading '"+str(filename)+"' from -> "+str(apkUrl)+" ... ")
    
    response = requests.get(apkUrl, stream=True, headers=headers)
    with open(filename, 'wb') as out_file:
        shutil.copyfileobj(response.raw, out_file)
    del response

    print("DEBUG: file name: " + filename)

    sha256_hash = hashlib.sha256()
    with open(filename,"rb") as f: # source: https://www.quickprogrammingtips.com/python/how-to-calculate-sha256-hash-of-a-file-in-python.html
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
        sha256_hash = str(sha256_hash.hexdigest())

    sha256_hash = str(sha256_hash)
    print("DEBUG: file hash: " + sha256_hash)
    
    try:
        apkFiles = list(workingDir.glob('*.apk'))
        pprint(apkFiles)
        
        if len(apkFiles) > 0:
            for apkFileTemp in apkFiles:
                try:
                    print("DEBUG: apk file '"+str(apkFileTemp.absolute())+"' -> size: "+str(apkFileTemp.stat().st_size))
                    
                    sa = StaticAnalysis(str(apkFileTemp.absolute())) # init ExodusPrivacy StaticAnalysis for 'apkFileTemp'
                    sa.print_apk_infos()
                    sa.print_embedded_trackers()
                    
                    
                    
                    try:
                        pprint(sa.signatures[0])
                        
                        with open(str(Path(workingDir / "tracker-signatures.json").absolute()), "w+", encoding="utf-8") as fh:
                            fh.write(str(json.dumps(sa.signatures, indent=4)))
                    except Exception as e:
                        print("ERROR: trying to save tracker signatures -> error: "+str(e))
                    
                except Exception as e:
                    print("ERROR: while processing '"+str(apkFileTemp)+"' -> error: "+str(e))
    except Exception as e:
        print("ERROR: "+str(e))

else:
    print("ERROR: content of codeberg json response is invalid! ")

    try:
        pprint(str(searchCodebergReq.headers))
        pprint(str(searchCodebergReq.text))
    except Exception as e:
        print("ERROR: failed to print request raw data to console! -> error: "+str(e))

    sys.exit(1)
