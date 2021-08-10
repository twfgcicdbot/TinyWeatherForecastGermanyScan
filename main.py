"""

@title TinyWeatherForecastGermany - exodusprivacy apk scan

@author Jean-Luc Tibaux (https://gitlab.com/eUgEntOptIc44)

@license GPLv3

@since August 2021

No warranty or guarantee of any kind provided. Use at your own risk.
Not meant to be used in commercial or in general critical/productive environments at all.

"""

from datetime import datetime
from pprint import pprint
import hashlib
import json
import random
import sys
import time

from bs4 import BeautifulSoup
import requests

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

searchResultCodebergJson = json.loads(str(searchCodebergReq.text))
#pprint(searchResultCodebergJson)
print("DEBUG: fetched Codeberg data")

if len(str(searchResultExodusJson)) > 0 and len(searchResultCodebergJson) > 0 and searchResultCodebergJson != None:
    twfgJson = searchResultExodusJson["results"][0]
    
    pprint(twfgJson)
    
    apkUrl = str(searchResultCodebergJson[0]["assets"][0]["browser_download_url"])
    filename = str(searchResultCodebergJson[0]["assets"][0]["name"])

    response = requests.get(apkUrl, stream=True)
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
