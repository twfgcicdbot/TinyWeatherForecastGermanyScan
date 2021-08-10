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

from dateutil.tz import tzutc # timezone UTC -> docs: https://dateutil.readthedocs.io/en/stable/tz.html#dateutil.tz.tzutc
from bs4 import BeautifulSoup
import requests

import markdown
from markdown.extensions.toc import TocExtension

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
    
    # sha256_hash = hashlib.sha256()
    # with open(filename,"rb") as f: # source: https://www.quickprogrammingtips.com/python/how-to-calculate-sha256-hash-of-a-file-in-python.html
    #     # Read and update hash string value in blocks of 4K
    #     for byte_block in iter(lambda: f.read(4096),b""):
    #         sha256_hash.update(byte_block)
    #     sha256_hash = str(sha256_hash.hexdigest())

    # sha256_hash = str(sha256_hash)
    # logging.debug("file hash: " + sha256_hash)
    
    try:
        apkFiles = list(workingDir.glob('*.apk'))
        pprint(apkFiles)
        
        if len(apkFiles) > 0:
            for apkFileTemp in apkFiles:
                try:
                    logging.debug("apk file '"+str(apkFileTemp.absolute())+"' -> size: "+str(apkFileTemp.stat().st_size))
                    
                    resultDict = {}
                    resultMarkdown = ""
                    
                    analysisTemp = StaticAnalysis(str(apkFileTemp.absolute())) # init ExodusPrivacy StaticAnalysis for 'apkFileTemp'
                    
                    try:
                        analysisTemp.print_apk_infos()
                    except Exception as e:
                        logging.error("printing of 'apk_infos' to console failed! -> error: "+str(e))
                    
                    # --- start of apk_infos ---

                    try:
                        apkName = str(analysisTemp.get_app_name())
                        if apkName != "None":
                            logging.debug("static analysis returned app name: "+str(apkName))
                            resultDict["name"] = apkName
                            resultMarkdown += "# " + apkName + "\n\n"
                        else:
                            resultMarkdown += "# apk name missing \n\n"
                            logging.error("parsing of 'get_app_name()' for apk '"+str(apkFileTemp)+"' failed! -> error: result is None!")
                    except Exception as e:
                        logging.error("parsing of 'get_app_name()' for apk '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                        resultMarkdown += "# apk name missing \n\n"

                    resultMarkdown += "\n\n[TOC]\n\n"
                    
                    resultMarkdown += "\n## Metadata \n"

                    try:
                        apkPackage = str(analysisTemp.get_package())
                        if apkPackage != "None":
                            logging.debug("static analysis returned app package: "+str(apkPackage))
                            resultDict["package"] = apkPackage
                            resultMarkdown += "* **package**: " + apkPackage + "\n"
                        else:
                            resultMarkdown += "* **package**: *unknown* \n"
                            logging.error("parsing of 'get_package()' for apk '"+str(apkFileTemp)+"' failed! -> error: result is None!")    
                    except Exception as e:
                        logging.error("parsing of 'get_package()' for apk '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                        resultMarkdown += "* **package**: *unknown* \n"

                    try:
                        apkSum = str(analysisTemp.get_sha256())
                        if apkSum != "None":
                            logging.debug("static analysis returned apk hash (sha256): "+str(apkSum))
                            resultDict["hash_sha256"] = apkSum
                            resultMarkdown += "* **sha256 hash**: " + apkSum + "\n"
                        else:
                            resultMarkdown += "* **sha256 hash**: *unknown* \n"
                            logging.error("parsing of 'get_sha256()' for apk '"+str(apkFileTemp)+"' failed! -> error: result is None!")    
                    except Exception as e:
                        logging.error("parsing of 'get_sha256()' for apk '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                        resultMarkdown += "* **sha256 hash**: *unknown* \n"
                    
                    try:
                        apkVersion = str(analysisTemp.get_version())
                        if apkVersion != "None":
                            logging.debug("static analysis returned apk version: "+str(apkVersion))
                            resultDict["version"] = apkVersion
                            resultMarkdown += "* **version**: " + apkVersion + "\n"
                        else:
                            resultMarkdown += "* **version**: *unknown* \n"
                            logging.error("parsing of 'get_version()' for apk '"+str(apkFileTemp)+"' failed! -> error: result is None!")    
                    except Exception as e:
                        logging.error("parsing of 'get_version()' for apk '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                        resultMarkdown += "* **version**: *unknown* \n"
                    
                    try:
                        apkVersionCode = analysisTemp.get_version_code()
                        if apkVersionCode != None:
                            logging.debug("static analysis returned apk version code: "+str(apkVersionCode))
                            resultDict["version_code"] = apkVersionCode
                            resultMarkdown += "* **version code**: " + apkVersionCode + "\n"
                        else:
                            resultMarkdown += "* **version code**: *unknown* \n"
                            logging.error("parsing of 'get_version_code()' for apk '"+str(apkFileTemp)+"' failed! -> error: result is None!")    
                    except Exception as e:
                        logging.error("parsing of 'get_version_code()' for apk '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                        resultMarkdown += "* **version code**: *unknown* \n"
                    
                    try:
                        apkUID = str(analysisTemp.get_application_universal_id())
                        if apkUID != "None":
                            logging.debug("static analysis returned apk UID: "+str(apkUID))
                            resultDict["UID"] = apkUID
                            resultMarkdown += "* **app UID**: " + apkUID + " \n"
                        else:
                            resultMarkdown += "* **app UID**: *unknown* \n"
                            logging.error("parsing of 'get_application_universal_id()' (UID) for apk '"+str(apkFileTemp)+"' failed! -> error: result is None!")    
                    except Exception as e:
                        logging.error("parsing of 'get_application_universal_id()' (UID) for apk '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                        resultMarkdown += "* **app UID**: *unknown* \n"
                    
                    resultMarkdown += "\n## Permissions \n"
                 
                    try:
                        permissions = analysisTemp.get_permissions()
                        if permissions != None:
                            lenPermissions = len(permissions)

                            logging.debug("static analysis returned "+str(lenPermissions)+" permission(s) ")
                            resultMarkdown += "\n "+str(lenPermissions)+" permissions detected \n\n"
                            
                            resultDict["permissions"] = []
                            if lenPermissions > 0:
                                for permissionTemp in permissions:
                                    try:
                                        resultDict["permissions"].append(str(permissionTemp))
                                        resultMarkdown += "* "+str(permissionTemp)+" \n"
                                    except Exception as e:
                                        logging.error("saving of permission '"+str(permissionTemp)+"' of '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                            else:
                                logging.debug("skipping iteration of permissions as 'lenPermissions' is "+str(lenPermissions))
                        else:
                            resultMarkdown += "\n **failed** to detect permissions! \n\n"
                            logging.error("parsing of 'permissions' for apk '"+str(apkFileTemp)+"' failed! -> error: result is None!")
                    except Exception as e:
                        resultMarkdown += "\n **failed** to detect permissions! \n\n"
                        logging.error("parsing of 'permissions' for apk '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                    
                    resultMarkdown += "\n## Libraries \n"

                    try:
                        libraries = analysisTemp.get_libraries()
                        if libraries != None:
                            lenLibraries = len(libraries)
                            logging.debug("static analysis returned "+str(lenLibraries)+" libraries ")
                            resultMarkdown += "\n "+str(lenLibraries)+" libraries detected \n\n"

                            resultDict["libraries"] = []
                            if lenLibraries > 0:
                                for libraryTemp in libraries:
                                    try:
                                        resultDict["libraries"].append(str(libraryTemp))
                                        resultMarkdown += "* "+str(libraryTemp)+" \n"
                                    except Exception as e:
                                        logging.error("saving of library '"+str(libraryTemp)+"' of '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                            else:
                                logging.debug("skipping iteration of libraries as 'lenLibraries' is "+str(lenLibraries))
                        else:
                            resultMarkdown += "\n **failed** to detect libraries! \n\n"
                            logging.error("parsing of 'libraries' for apk '"+str(apkFileTemp)+"' failed! -> error: result is None!")
                    except Exception as e:
                        resultMarkdown += "\n **failed** to detect libraries! \n\n"
                        logging.error("parsing of 'libraries' for apk '"+str(apkFileTemp)+"' failed! -> error: "+str(e))

                    resultMarkdown += "\n## Certificates \n"

                    try:
                        certificates = analysisTemp.get_certificates()
                        if certificates != None:
                            lenCertificates = len(certificates)

                            logging.debug("static analysis returned "+str(lenCertificates)+" certificate(s) ")
                            resultMarkdown += "\n "+str(lenCertificates)+" certificate(s) detected \n\n"

                            resultDict["certificates"] = []

                            if lenCertificates > 0:
                                for certificateTemp in certificates:
                                    certificateTempStr = str(certificateTemp)
                                    certificateTempMd = certificateTempStr
                                    try:
                                        certificateTempStr = 'Issuer: {} \n Subject: {} \n Fingerprint: {} \n Serial: {}'.format(certificateTemp.issuer, certificateTemp.subject, certificateTemp.fingerprint, certificateTemp.serial)
                                        certificateTempMd = '\n<details>\n<summary>click to expand</summary>\n\n<b>Issuer</b>: {} \n\n<b>Subject</b>: {} \n\n<b>Fingerprint</b>: {} \n\n<b>Serial</b>: {}\n\n</details>\n\n'.format(certificateTemp.issuer, certificateTemp.subject, certificateTemp.fingerprint, certificateTemp.serial)
                                    except Exception as e:
                                        logging.warning("serializing of certificate '"+str(certificateTemp)+"' of '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                                        logging.warning(" using fallback solution ")
                                    try:
                                        resultDict["certificates"].append(str(certificateTempStr))
                                        resultMarkdown += str(certificateTempMd)+" \n\n"
                                    except Exception as e:
                                        logging.error("saving of certificate '"+str(certificateTemp)+"' of '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                            else:
                                logging.debug("skipping iteration of certificates as 'lenCertificates' is "+str(lenCertificates))
                        else:
                            resultMarkdown += "\n **failed** to detect certificates! \n\n"
                            logging.error("parsing of 'certificates' for apk '"+str(apkFileTemp)+"' failed! -> error: result is None!")    
                    except Exception as e:
                        resultMarkdown += "\n **failed** to detect certificates! \n\n"
                        logging.error("parsing of 'certificates' for apk '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                    
                    # --- end of apk_infos ---
                    
                    # --- start of embedded_trackers ---
                    
                    try:
                        analysisTemp.print_embedded_trackers()
                    except Exception as e:
                        logging.error("printing of 'embedded_trackers' to console failed! -> error: "+str(e))                    
                    
                    resultMarkdown += "\n## Trackers \n"

                    try:
                        embeddedTrackers = analysisTemp.detect_trackers()
                        if embeddedTrackers != None:
                            lenEmbeddedTrackers = len(embeddedTrackers)

                            logging.debug("static analysis returned "+str(lenEmbeddedTrackers)+" tracker(s): "+str(embeddedTrackers))
                            resultMarkdown += "\n<details>\n<summary>"+str(lenEmbeddedTrackers)+" tracker(s) detected</summary>\n\n<ul>"
                            resultDict["trackers"] = []

                            if lenEmbeddedTrackers > 0:
                                for embeddedTrackerTemp in embeddedTrackers:
                                    try:
                                        resultDict["trackers"].append(str(embeddedTrackerTemp))
                                        resultMarkdown += "<li>"+str(embeddedTrackerTemp)+"</li> \n"
                                    except Exception as e:
                                        logging.error("saving of tracker '"+str(embeddedTrackerTemp)+"' from '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                            else:
                                logging.debug("skipping iteration of trackers as 'lenEmbeddedTrackers' is "+str(lenEmbeddedTrackers))
                            
                            resultMarkdown += "\n</ul>\n</details>\n\n"
                        else:
                            resultMarkdown += "\n **failed** to detect trackers! \n\n"
                            logging.error("parsing of 'detect_trackers()' for apk '"+str(apkFileTemp)+"' failed! -> error: result is None!")    
                    except Exception as e:
                        resultMarkdown += "\n **failed** to detect trackers! \n\n"
                        logging.error("parsing of 'detect_trackers()' for apk '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                    
                    # --- end of embedded_trackers ---

                    # --- start of embedded_classes ---
                    
                    resultMarkdown += "\n## Classes \n"

                    try:
                        embeddedClasses = analysisTemp.get_embedded_classes()
                        if embeddedClasses != None:
                            lenEmbeddedClasses = len(embeddedClasses)

                            logging.debug("static analysis returned "+str(lenEmbeddedClasses)+" class(es): "+str(embeddedClasses))
                            resultMarkdown += "\n<details>\n<summary>"+str(lenEmbeddedClasses)+" class(es) detected</summary>\n\n<ul>"
                            
                            resultDict["classes"] = []

                            if lenEmbeddedClasses > 0:
                                for embeddedClassTemp in embeddedClasses:
                                    try:
                                        resultDict["classes"].append(str(embeddedClassTemp))
                                        resultMarkdown += "<li>"+str(embeddedClassTemp)+"</li> \n"
                                    except Exception as e:
                                        logging.error("saving of class '"+str(embeddedClassTemp)+"' of '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                            else:
                                logging.debug("skipping iteration of classes as 'lenEmbeddedClasses' is "+str(lenEmbeddedClasses))
                            
                            resultMarkdown += "\n</ul>\n</details>"
                        else:
                            resultMarkdown += "\n **failed** to detect classes! \n\n"
                            logging.error("parsing of 'get_embedded_classes()' for apk '"+str(apkFileTemp)+"' failed! -> error: result is None!")    
                    except Exception as e:
                        resultMarkdown += "\n **failed** to detect classes! \n\n"
                        logging.error("parsing of 'get_embedded_classes()' for apk '"+str(apkFileTemp)+"' failed! -> error: "+str(e))
                    
                    # --- end of embedded_classes ---

                    resultMarkdown += "\n\n This report was generated on " + str(datetime.now(tzutc()).strftime("%Y-%m-%d at %H:%M (%Z)")) + " using [`exodus-core`](https://github.com/Exodus-Privacy/exodus-core/).\n"

                    try:
                        #pprint(analysisTemp.signatures[0])                        

                        try:
                            trackerSignatures = list(analysisTemp.signatures) # list of named tuples -> also see: https://stackoverflow.com/questions/26180528/convert-a-namedtuple-into-a-dictionary
                        except Exception as e:
                            trackerSignatures = []
                            logging.error("while trying to save tracker signatures -> error: "+str(e))

                        if len(trackerSignatures) > 0:
                            trackerSignaturesRaw = trackerSignatures
                            trackerSignatures = []
                            for trackerSignatureTemp in trackerSignaturesRaw:
                                try:
                                    trackerSignatures.append(trackerSignatureTemp._asdict())
                                except Exception as e:
                                    logging.error("while trying to parse tracker signature '"+str(trackerSignatureTemp)+"' -> error: "+str(e))
                        else:
                            logging.error("while trying to parse tracker signatures -> error: data length is invalid!")

                        with open(str(Path(workingDir / "tracker-signatures.json").absolute()), "w+", encoding="utf-8") as fh:
                            fh.write(str(json.dumps(trackerSignatures, indent=4)))

                        resultMarkdown += "\nThe analysis has been conducted using "+str(len(analysisTemp.signatures))+" tracker signatures by ExodusPrivacy."
                    except Exception as e:
                        logging.error("while trying to save tracker signatures -> error: "+str(e))

                    try:
                        #pprint(resultDict)                        
                        with open(str(Path(workingDir / "analysis-result.json").absolute()), "w+", encoding="utf-8") as fh:
                            fh.write(str(json.dumps(resultDict, indent=4)))
                    except Exception as e:
                        logging.error("while trying to save analysis result as json file -> error: "+str(e))
                    
                    try:
                        #pprint(resultMarkdown)                        
                        with open(str(Path(workingDir / "analysis-result.md").absolute()), "w+", encoding="utf-8") as fh:
                            fh.write(str(resultMarkdown))
                    except Exception as e:
                        logging.error("while trying to save analysis result as markdown file -> error: "+str(e))

                    try:
                        reportFileHtml = """
<!DOCTYPE html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width, initial-scale=1.0"><title>TinyWeatherForecastGermany | open source android app using open weather data from Deutscher Wetterdienst (DWD)</title><link rel=apple-touch-icon sizes=180x180 href=images/apple-touch-icon.png><link rel=icon type=image/png sizes=32x32 href=images/favicon-32x32.png><link rel=icon type=image/png sizes=16x16 href=images/favicon-16x16.png><link rel=manifest href=images/site.webmanifest><link rel=mask-icon href=images/safari-pinned-tab.svg color=#293235><link rel="shortcut icon" href=images/favicon.ico><meta name=apple-mobile-web-app-title content=TinyWeatherForecastGermany><meta name=application-name content=TinyWeatherForecastGermany><meta name=msapplication-TileColor content=#293235><meta name=msapplication-config content=images/browserconfig.xml><meta name=theme-color content=#293235><link rel=stylesheet href=https://tinyweatherforecastgermanygroup.gitlab.io/index/css/style_5b8f9938.min.css><meta name=description content="TinyWeatherForecastGermany - android app using DWD open weather data"><meta name=keywords content="dwd, Deutscher Wetterdienst, android, app, open source, weather, wetter, rainradar, regenradar, map, charts, open data, germany, deutschland, allemagne, duitsland"><meta name=robots content="index, follow"><meta name=audience content=all><meta name=thumbnail content=images/icon.png><meta name=revisit-after content="2 days"><meta name=page-topic content="Android App"><meta name=google-site-verification content=MdTS4FWQKzHI34uGnZwU87K2sivqjVQjGe3E-yGd09Y><meta name=pubdate content=20210810><meta property=og:title content="TinyWeatherForecastGermany - android app using DWD open weather data"><meta property=og:description content="TinyWeatherForecastGermany is an open source android app using open weather data provided by Deutscher Wetterdienst (DWD)"><meta property=og:image content=images/twfg-repository-open-graph-graphic.png><meta content=https://tinyweatherforecastgermanygroup.gitlab.io/index/ property=og:url><meta name=twitter:title content="TinyWeatherForecastGermany - android app using DWD open weather data"><meta name=twitter:description content="TinyWeatherForecastGermany is an open source android app using open weather data provided by Deutscher Wetterdienst (DWD)"><meta name=twitter:image content=images/twfg-repository-open-graph-graphic.png><meta name=twitter:card content=summary_large_image><script type=application/ld+json>
    {
        "@context" : "http://schema.org",
        "@type" : "MobileApplication",
        "applicationCategory" : "Weather",
        "genre" : "Weather",
        "name" : "TinyWeatherForecastGermany",
        "description" : "Weather forecast based on open data from the Deutscher Wetterdienst.",
        "operatingSystem" : "Android 4.4+",
        "installUrl" : "https://f-droid.org/packages/de.kaffeemitkoffein.tinyweatherforecastgermany/",
        "image" : "https://tinyweatherforecastgermanygroup.gitlab.io/index/images/icon.png",
        "screenshot" : "https://f-droid.org/repo/de.kaffeemitkoffein.tinyweatherforecastgermany/en-US/phoneScreenshots/1.png",
        "creator" : {
            "@context" : "http://schema.org",
            "@type" : "Person",
            "name" : "Pawel Dube (Starfish)",
            "url" : "https://codeberg.org/Starfish"
        },
        "sourceOrganization" : {
            "@context" : "http://schema.org",
            "@type" : "Organization",
            "name" : "TinyWeatherForecastGermanyGroup",
            "url" : "https://gitlab.com/tinyweatherforecastgermanygroup"
            },
        "offers" : {
            "@type" : "Offer",
            "url" : "https://f-droid.org/packages/de.kaffeemitkoffein.tinyweatherforecastgermany/",
            "price": 0,
            "priceCurrency" : "EUR"
        }
    }
</script></head><body><article>
                        """
                        reportFileHtml += markdown.markdown(resultMarkdown, extensions=['extra', 'sane_lists', TocExtension(baselevel=3, title='Table of contents', anchorlink=True)])
                        
                        reportFileHtml += """
</article></body></html>
                        """

                        with open(str(Path(workingDir / "index.html").absolute()), "w+", encoding="utf-8") as fh:
                            fh.write(str(reportFileHtml))
                    except Exception as e:
                        logging.error("while trying to save analysis result as html file -> error: "+str(e))

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
