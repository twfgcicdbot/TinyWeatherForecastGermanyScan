"""

**title**: TinyWeatherForecastGermany - exodusprivacy local apk scan

**author**: Jean-Luc Tibaux (https://gitlab.com/eUgEntOptIc44)

**license**: GPLv3 (https://github.com/twfgcicdbot/TinyWeatherForecastGermanyScan/blob/d19eb5eeeda3649ecd93a3b52f018878dd24ec81/LICENSE)

**since**: August 2021

**url**: https://twfgcicdbot.github.io/TinyWeatherForecastGermanyScan/

## Disclaimer

No warranty or guarantee of any kind provided. Use at your own risk only.
Not meant to be used in commercial or in general critical/productive environments at all.

"""

import json
import logging
import shutil
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from pprint import pprint
from random import SystemRandom

import htmlmin
import markdown
import regex
import requests
from bs4 import BeautifulSoup
from dateutil.tz import (
    tzutc,  # timezone UTC -> docs: https://dateutil.readthedocs.io/en/stable/tz.html#dateutil.tz.tzutc
)
from exodus_core.analysis.static_analysis import StaticAnalysis
from markdown.extensions.toc import TocExtension

from permissions_en import AOSP_PERMISSIONS_EN

# required to use cryptographically secure random functions
cryptogen = SystemRandom()

working_dir = Path("TinyWeatherForecastGermanyScan")
# create directory if not exists
working_dir.mkdir(parents=True, exist_ok=True)

log_p = working_dir / "debug.log"
try:
    logging.basicConfig(format='%(asctime)-s %(levelname)s [%(name)s]: %(message)s',
                        level=logging.DEBUG,
                        handlers=[
                            logging.FileHandler(str(log_p.absolute()),
                                                encoding="utf-8"),
                            logging.StreamHandler()
                        ])
except Exception as e:
    logging.error(f"while logger init! -> error: {e}")

# sources of user agent data -> License: MIT
#  -> https://github.com/tamimibrahim17/List-of-user-agents/blob/master/Chrome.txt
#  -> https://github.com/tamimibrahim17/List-of-user-agents/blob/master/Firefox.txt
user_agents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2919.83 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2866.71 Safari/537.36", "Mozilla/5.0 (X11; Ubuntu; Linux i686 on x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2820.59 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2762.73 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2656.18 Safari/537.36", "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/44.0.2403.155 Safari/537.36", "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.1 Safari/537.36", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36", "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36", "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2226.0 Safari/537.36", "Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10; rv:33.0) Gecko/20100101 Firefox/33.0", "Mozilla/5.0 (Windows ME 4.9; rv:31.0) Gecko/20100101 Firefox/31.7", "Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/31.0", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20130401 Firefox/31.0", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:28.0) Gecko/20100101 Firefox/31.0", "Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0",
               "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:29.0) Gecko/20120101 Firefox/29.0", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/29.0", "Mozilla/5.0 (X11; OpenBSD amd64; rv:28.0) Gecko/20100101 Firefox/28.0", "Mozilla/5.0 (X11; Linux x86_64; rv:28.0) Gecko/20100101  Firefox/28.0", "Mozilla/5.0 (Windows NT 6.1; rv:27.3) Gecko/20130101 Firefox/27.3", "Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:27.0) Gecko/20121011 Firefox/27.0", "Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/26.0", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:25.0) Gecko/20100101 Firefox/25.0", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:25.0) Gecko/20100101 Firefox/25.0", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0", "Mozilla/5.0 (Windows NT 6.0; WOW64; rv:24.0) Gecko/20100101 Firefox/24.0", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0", "Mozilla/5.0 (Windows NT 6.2; rv:22.0) Gecko/20130405 Firefox/23.0", "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:23.0) Gecko/20130406 Firefox/23.0", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:23.0) Gecko/20131011 Firefox/23.0", "Mozilla/5.0 (Windows NT 6.2; rv:22.0) Gecko/20130405 Firefox/22.0", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:22.0) Gecko/20130328 Firefox/22.0", "Mozilla/5.0 (Windows NT 6.1; rv:22.0) Gecko/20130405 Firefox/22.0", "Mozilla/5.0 (Microsoft Windows NT 6.2.9200.0); rv:22.0) Gecko/20130405 Firefox/22.0", "Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:16.0.1) Gecko/20121011 Firefox/21.0.1", "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:16.0.1) Gecko/20121011 Firefox/21.0.1", "Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:21.0.0) Gecko/20121011 Firefox/21.0.0", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:21.0) Gecko/20130331 Firefox/21.0", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:21.0) Gecko/20100101 Firefox/21.0", "Mozilla/5.0 (X11; Linux i686; rv:21.0) Gecko/20100101 Firefox/21.0"]

cryptogen.shuffle(user_agents)

user_agent = str(cryptogen.choice(user_agents))

logging.debug(f"querying data as '{user_agent}' ")

headers = {
    "User-Agent": user_agent,
    "DNT": "1"
}

search_cb_req = requests.get(
    "https://codeberg.org/api/v1/repos/Starfish/TinyWeatherForecastGermany/releases?limit=1",
    headers=headers,
    timeout=20)

try:
    search_cb_json = search_cb_req.json()
    # pprint(searchResultCodebergJson)
    logging.debug("fetched Codeberg data")
except Exception as e:
    logging.error(f"codeberg api request failed! -> error: {e} ")

if len(search_cb_json) == 1 and search_cb_json is not None:
    twfg_json = search_cb_json[0]

    pprint(twfg_json)

    if twfg_json is None:
        logging.error(
            "content of key 'results' in codeberg json response is 'None' ")

        try:
            pprint(str(search_cb_req.headers))
            pprint(str(search_cb_req.text))
        except Exception as e:
            logging.error(
                f"failed to print request raw data to console! -> error: {e}")

        sys.exit(1)

    twfg_asset = twfg_json["assets"][0]
    apk_url = str(twfg_asset["browser_download_url"])
    apk_name = str(twfg_asset["name"])

    apk_path = working_dir / apk_name
    if not apk_path.exists():
        logging.debug(f"downloading '{apk_name}' from -> {apk_url} ... ")

        response = requests.get(apk_url, stream=True,
                                headers=headers, timeout=30)
        with open(str(apk_path.absolute()), 'wb') as out_file:
            shutil.copyfileobj(response.raw, out_file)
        del response
    else:
        logging.info(f"skipped download of '{apk_name}' file"
                     f" '{apk_path}' already exists ")

    logging.debug("file name: " + apk_name)
    logging.debug("file path: " + str(apk_path.absolute()))

    try:
        apk_files = list(working_dir.glob('*.apk'))
        pprint(apk_files)

        if len(apk_files) > 0:
            for apk_file_temp in apk_files:
                try:
                    logging.debug(f"apk file '{apk_file_temp.absolute()}' "
                                  f"-> size: {apk_file_temp.stat().st_size}")

                    result_dict = {}
                    result_markdown = ""

                    # init ExodusPrivacy StaticAnalysis for 'apkFileTemp'
                    analysis_temp = StaticAnalysis(
                        str(apk_file_temp.absolute()))

                    try:
                        analysis_temp.print_apk_infos()
                    except Exception as e:
                        logging.error(f"printing of 'apk_infos' to console failed!"
                                      f" -> error: {e}")

                    # --- start of apk_infos ---

                    try:
                        apk_name = str(analysis_temp.get_app_name())
                        if apk_name != "None":
                            logging.debug(f"static analysis returned app name:"
                                          f" {apk_name} ")
                            result_dict["name"] = apk_name
                            result_markdown += "# " + apk_name + "\n\n"
                        else:
                            result_markdown += "# apk name missing \n\n"
                            logging.error(
                                f"parsing of 'get_app_name()' for apk '{apk_file_temp}' failed! -> error: result is 'None'!")
                    except Exception as e:
                        logging.error(
                            f"parsing of 'get_app_name()' for apk '{apk_file_temp}' failed! -> error: {e}")
                        result_markdown += "# apk name missing \n\n"

                    result_markdown += "\n\n[TOC]\n\n"

                    result_markdown += "\n## Metadata\n\n"

                    try:
                        apk_package = str(analysis_temp.get_package())
                        if apk_package != "None":
                            logging.debug(
                                f"static analysis returned app package: {apk_package}")
                            result_dict["package"] = apk_package
                            result_markdown += f"* **package**: [{apk_package}](https://f-droid.org/packages/{apk_package}/)" + \
                                "{ title='F-Droid Store package site' #fdroidproductpage } \n"
                        else:
                            result_markdown += "* **package**: *unknown* \n"
                            logging.error(
                                f"parsing of 'get_package()' for apk '{apk_file_temp}' failed! -> error: result is 'None'!")
                    except Exception as e:
                        logging.error(
                            f"parsing of 'get_package()' for apk '{apk_file_temp}' failed! -> error: {e}")
                        result_markdown += "* **package**: *unknown* \n"

                    try:
                        apk_sum = str(analysis_temp.get_sha256())
                        if apk_sum != "None":
                            logging.debug(
                                f"static analysis returned apk hash (sha256): {apk_sum}")
                            result_dict["hash_sha256"] = apk_sum
                            result_markdown += f"* **sha256 hash**: [{apk_sum}](https://www.virustotal.com/gui/file/{apk_sum}/detection)" + \
                                "{ title='click to get the VirusTotal report' #virustotalhash } \n"

                            try:
                                sha_path = Path(working_dir / "sha256.html")
                                with open(str(sha_path.absolute()), "w+", encoding="utf-8") as fh:
                                    fh.write(str(apk_sum))
                            except Exception as e:
                                logging.error(
                                    f"failed to write sha256 hash to '{sha_path}' -> error: {e}")
                        else:
                            result_markdown += "* **sha256 hash**: *unknown* \n"
                            logging.error(
                                f"parsing of 'get_sha256()' for apk '{apk_file_temp}' failed! -> error: result is 'None'!")
                    except Exception as e:
                        logging.error(
                            f"parsing of 'get_sha256()' for apk '{apk_file_temp}' failed! -> error: {e}")
                        result_markdown += "* **sha256 hash**: *unknown* \n"

                    try:
                        apk_version = str(analysis_temp.get_version())
                        if apk_version != "None":
                            logging.debug(
                                f"static analysis returned apk version: {apk_version}")
                            result_dict["version"] = apk_version
                            result_markdown += f"* **version**: {apk_version}\n"
                        else:
                            result_markdown += "* **version**: *unknown* \n"
                            logging.error(
                                f"parsing of 'get_version()' for apk '{apk_file_temp}' failed! -> error: result is 'None'!")
                    except Exception as e:
                        logging.error(
                            f"parsing of 'get_version()' for apk '{apk_file_temp}' failed! -> error: {e}")
                        result_markdown += "* **version**: *unknown* \n"

                    try:
                        apk_v_code = str(analysis_temp.get_version_code())
                        if apk_v_code is not None:
                            logging.debug(
                                f"static analysis returned apk version code: {apk_v_code}")
                            result_dict["version_code"] = apk_v_code
                            result_markdown += f"* **version code**: {apk_v_code}\n"
                        else:
                            result_markdown += "* **version code**: *unknown* \n"
                            logging.error(
                                f"parsing of 'get_version_code()' for apk '{apk_file_temp}' failed! -> error: result is None!")
                    except Exception as e:
                        logging.error(
                            f"parsing of 'get_version_code()' for apk '{apk_file_temp}' failed! -> error: {e}")
                        result_markdown += "* **version code**: *unknown* \n"

                    try:
                        apk_uid = str(
                            analysis_temp.get_application_universal_id())
                        if apk_uid != "None":
                            logging.debug(
                                f"static analysis returned apk UID: {apk_uid}")
                            result_dict["UID"] = apk_uid
                            result_markdown += "* [**app UID**](https://stackoverflow.com/a/5709279){ title='android app UID explanation on StackOverflow' }: " + apk_uid + " \n"
                        else:
                            result_markdown += "* [**app UID**](https://stackoverflow.com/a/5709279){ title='android app UID explanation on StackOverflow' }: *unknown* \n"
                            logging.error(
                                f"parsing of 'get_application_universal_id()' (UID) for apk '{apk_file_temp}' failed! -> error: result is None!")
                    except Exception as e:
                        logging.error(
                            f"parsing of 'get_application_universal_id()' (UID) for apk '{apk_file_temp}' failed! -> error: {e}")
                        result_markdown += "* **app UID**: *unknown* \n"

                    logging.debug("working on permissions ... ")

                    result_markdown += "\n## Permissions \n"

                    try:
                        permissions = analysis_temp.get_permissions()
                        if permissions is not None:
                            lenPermissions = len(permissions)

                            logging.debug(
                                f"static analysis returned {lenPermissions} permission(s) ")
                            result_markdown += f"\n {lenPermissions} permissions detected \n\n"

                            result_dict["permissions"] = []
                            if lenPermissions > 0:
                                # pprint(permissions)
                                result_markdown += '<ul id="permissions-list">'

                                for permissionTemp in permissions:
                                    try:
                                        permissionDictTemp = AOSP_PERMISSIONS_EN["permissions"][str(
                                            permissionTemp).strip()]

                                        permissionDesc = str(
                                            permissionDictTemp["description"]).replace("\n", "").strip()
                                        permissionDesc = regex.sub(
                                            r"(?im)\n", "", permissionDesc)
                                        while "  " in permissionDesc:
                                            permissionDesc = regex.sub(
                                                r"(?im)(  )+", " ", permissionDesc)
                                        permissionDictTemp["description"] = permissionDesc

                                        pprint(permissionDictTemp)
                                    except Exception as e:
                                        permissionDictTemp = {
                                            "name": str(permissionTemp)}
                                        permissionDesc = ""
                                        logging.error("parsing of exodus knowledge data for permission '"+str(
                                            permissionTemp)+"' of '"+str(apk_file_temp)+"' failed! -> error: "+str(e))

                                    perm_icon = ''
                                    if 'icon' in permissionDictTemp:
                                        perm_icon = str(permissionDictTemp["icon"]).replace(
                                            "\n", "").strip()
                                    else:
                                        logging.debug(
                                            f" failed to find icon for permission '{permissionTemp}' -> dict keys: {list(permissionDictTemp.keys())} ")

                                    try:
                                        result_dict["permissions"].append(
                                            permissionDictTemp)
                                        result_markdown += '<li>' + \
                                            str(perm_icon)+' <b class="permission-title">' + \
                                            str(permissionTemp)+'</b> '

                                        if len(str(permissionDesc).lower().replace("none", "")) > 5:
                                            result_markdown += '<p id="permission-desc-'+regex.sub(r"(?im)[^A-z0-9]+", "", str(
                                                permissionTemp))+'" class="permission-description">'+permissionDesc+"</p>"

                                        result_markdown += "</li>\n"
                                    except Exception as e:
                                        logging.error("saving of permission '"+str(permissionTemp)+"' of '"+str(
                                            apk_file_temp)+"' failed! -> error: "+str(e))

                                result_markdown += '</ul>'
                            else:
                                logging.debug(
                                    "skipping iteration of permissions as 'lenPermissions' is "+str(lenPermissions))
                        else:
                            result_markdown += "\n **failed** to detect permissions! \n\n"
                            logging.error("parsing of 'permissions' for apk '" +
                                          str(apk_file_temp)+"' failed! -> error: result is None!")
                    except Exception as e:
                        result_markdown += "\n **failed** to detect permissions! \n\n"
                        logging.error("parsing of 'permissions' for apk '" +
                                      str(apk_file_temp)+"' failed! -> error: "+str(e))

                    logging.debug("working on libraries ... ")

                    result_markdown += "\n## Libraries \n"

                    try:
                        libraries = analysis_temp.get_libraries()
                        if libraries is not None:
                            len_libraries = len(libraries)
                            logging.debug(
                                f"static analysis returned {len_libraries} libraries ")
                            result_markdown += f"\n {len_libraries} libraries detected \n\n"

                            result_dict["libraries"] = []
                            if len_libraries > 0:
                                for libraryTemp in libraries:
                                    try:
                                        result_dict["libraries"].append(
                                            str(libraryTemp))
                                        result_markdown += "* " + \
                                            str(libraryTemp)+" \n"
                                    except Exception as e:
                                        logging.error("saving of library '"+str(libraryTemp)+"' of '"+str(
                                            apk_file_temp)+"' failed! -> error: "+str(e))
                            else:
                                logging.debug(
                                    "skipping iteration of libraries as 'lenLibraries' is "+str(len_libraries))
                        else:
                            result_markdown += "\n **failed** to detect libraries! \n\n"
                            logging.error("parsing of 'libraries' for apk '" +
                                          str(apk_file_temp)+"' failed! -> error: result is None!")
                    except Exception as e:
                        result_markdown += "\n **failed** to detect libraries! \n\n"
                        logging.error("parsing of 'libraries' for apk '" +
                                      str(apk_file_temp)+"' failed! -> error: "+str(e))

                    result_markdown += "\n## Certificates\n"

                    try:
                        certificates = analysis_temp.get_certificates()
                        if certificates is not None:
                            len_certs = len(certificates)

                            logging.debug(
                                "static analysis returned "+str(len_certs)+" certificate(s) ")
                            result_markdown += "\n " + \
                                str(len_certs)+" certificate(s) detected \n\n"

                            result_dict["certificates"] = []

                            if len_certs > 0:
                                for certificateTemp in certificates:
                                    certificateTempStr = str(certificateTemp)
                                    cert_temp_md = certificateTempStr
                                    try:
                                        certificateTempStr = 'Issuer: {} \n Subject: {} \n Fingerprint: {} \n Serial: {}'.format(
                                            certificateTemp.issuer, certificateTemp.subject, certificateTemp.fingerprint, certificateTemp.serial)

                                        if str(certificateTemp.issuer).strip().lower() == str(certificateTemp.subject).strip().lower():
                                            cert_temp_md = '\n<details class="cert-details">\n<summary>click to expand</summary>\n\n<b>Issuer</b>: {} <br><b>Fingerprint</b>: <span>{}</span> <br><b>Serial</b>: {}<br></details>\n'.format(
                                                certificateTemp.issuer, certificateTemp.fingerprint, certificateTemp.serial)
                                        else:
                                            cert_temp_md = '\n<details class="cert-details">\n<summary>click to expand</summary>\n\n<b>Issuer</b>: {} <br><b>Subject</b>: {} <br><b>Fingerprint</b>: <span>{}</span> <br><b>Serial</b>: {}<br></details>\n'.format(
                                                certificateTemp.issuer, certificateTemp.subject, certificateTemp.fingerprint, certificateTemp.serial)
                                    except Exception as e:
                                        logging.warning("serializing of certificate '"+str(
                                            certificateTemp)+"' of '"+str(apk_file_temp)+"' failed! -> error: "+str(e))
                                        logging.warning(
                                            " using fallback solution ")
                                    try:
                                        result_dict["certificates"].append(
                                            str(certificateTempStr))
                                        result_markdown += str(
                                            cert_temp_md)+" \n\n"
                                    except Exception as e:
                                        logging.error("saving of certificate '"+str(certificateTemp)+"' of '"+str(
                                            apk_file_temp)+"' failed! -> error: "+str(e))
                            else:
                                logging.debug(
                                    "skipping iteration of certificates as 'lenCertificates' is "+str(len_certs))
                        else:
                            result_markdown += "\n **failed** to detect certificates! \n\n"
                            logging.error("parsing of 'certificates' for apk '" +
                                          str(apk_file_temp)+"' failed! -> error: result is None!")
                    except Exception as e:
                        result_markdown += "\n **failed** to detect certificates! \n\n"
                        logging.error("parsing of 'certificates' for apk '" +
                                      str(apk_file_temp)+"' failed! -> error: "+str(e))

                    # --- end of apk_infos ---

                    # --- start of embedded_trackers ---

                    logging.debug("working on embedded_trackers ... ")

                    try:
                        analysis_temp.print_embedded_trackers()
                    except Exception as e:
                        logging.error(
                            f"printing of 'embedded_trackers' to console failed! -> error: {e} ")

                    result_markdown += "\n## Trackers\n"

                    try:
                        embeddedTrackers = analysis_temp.detect_trackers()
                        if embeddedTrackers is not None:
                            lenEmbeddedTrackers = len(embeddedTrackers)

                            logging.debug(
                                "static analysis returned "+str(lenEmbeddedTrackers)+" tracker(s): "+str(embeddedTrackers))
                            result_markdown += "\n<details>\n<summary>" + \
                                str(lenEmbeddedTrackers) + \
                                " tracker(s) detected</summary>\n\n<ul>"
                            result_dict["trackers"] = []

                            if lenEmbeddedTrackers > 0:
                                for embeddedTrackerTemp in embeddedTrackers:
                                    try:
                                        result_dict["trackers"].append(
                                            str(embeddedTrackerTemp))
                                        result_markdown += "<li>" + \
                                            str(embeddedTrackerTemp)+"</li> \n"
                                    except Exception as e:
                                        logging.error("saving of tracker '"+str(embeddedTrackerTemp)+"' from '"+str(
                                            apk_file_temp)+"' failed! -> error: "+str(e))
                            else:
                                logging.debug(
                                    "skipping iteration of trackers as 'lenEmbeddedTrackers' is "+str(lenEmbeddedTrackers))

                            result_markdown += "\n</ul>\n</details>\n\n"
                        else:
                            result_markdown += "\n **failed** to detect trackers! \n\n"
                            logging.error("parsing of 'detect_trackers()' for apk '" +
                                          str(apk_file_temp)+"' failed! -> error: result is None!")
                    except Exception as e:
                        result_markdown += "\n **failed** to detect trackers! \n\n"
                        logging.error("parsing of 'detect_trackers()' for apk '" +
                                      str(apk_file_temp)+"' failed! -> error: "+str(e))

                    # --- end of embedded_trackers ---

                    # --- start of embedded_classes ---

                    logging.debug("working on classes ... ")

                    result_markdown += "\n## Classes\n"

                    try:
                        embeddedClasses = analysis_temp.get_embedded_classes()
                        if embeddedClasses is not None:
                            lenEmbeddedClasses = len(embeddedClasses)

                            logging.debug(
                                "static analysis returned "+str(lenEmbeddedClasses)+" class(es): "+str(embeddedClasses))

                            # based on: https://gist.github.com/hrldcpr/2012250
                            def tree(): return defaultdict(tree)

                            def add_leafs(t, node_list):
                                for node in node_list:
                                    t = t[node]

                            classesTree = tree()
                            classes_dict = {}

                            for class_temp in embeddedClasses:
                                try:
                                    class_parts = list(class_temp.split("/"))
                                    add_leafs(classesTree, class_parts)
                                    classes_dict[class_parts[-1]] = class_temp.replace(
                                        class_parts[-1], '').strip('/')
                                except Exception as e:
                                    logging.error(
                                        f"failed to parse class -> error: {e}")

                            printClassesResult = f"<details><summary>{len(list(class_temp))} class(es) detected</summary>\n"

                            def print_classes_tree(tree, result, level):
                                for leaf in list(tree):
                                    lvl_indent = ""
                                    for level_index in range(0, level):
                                        lvl_indent += "-"

                                    sub_classes_count = len(
                                        list(dict(tree[leaf])))

                                    leaf_name = str(leaf)
                                    if level == 1:
                                        leaf_name = "<b>"+str(leaf_name)+"</b>"

                                    if sub_classes_count > 0:
                                        result += '\t<details><summary class="classes-tree-child" id="classes-tree-child-'+str(level+1)+'-'+str(
                                            sub_classes_count)+'" title="contains '+str(sub_classes_count)+' subclass(es)">|'+str(lvl_indent)+'> '+str(leaf_name)+'</summary>\n'
                                    else:
                                        docs_a = ''
                                        source_a = ''
                                        if leaf_name in classes_dict:
                                            class_path = classes_dict[leaf_name]
                                            if class_path[0:3] == 'de/' or 'nodomain/freeyourgadget' in class_path or 'org/astronomie' in class_path:
                                                source_a = ' -> <a class="subclass-source" title="open source at codeberg.org" target="_blank" href="https://codeberg.org/Starfish/TinyWeatherForecastGermany/src/branch/master/app/src/main/java/' + \
                                                    str(class_path)+'/' + \
                                                    str(leaf_name) + \
                                                    '.java">source</a>'
                                                docs_a = ' -> <a class="subclass-docs" title="open javadocs" target="_blank" href="https://tinyweatherforecastgermanygroup.gitlab.io/twfg-javadoc/' + \
                                                    str(class_path)+'/' + \
                                                    str(leaf_name) + \
                                                    '.html">docs</a>'

                                        result += '\t<span class="classes-tree-child subclass-child" id="classes-tree-child-'+str(level+1)+'-'+str(sub_classes_count)+'" data-path="'+str(
                                            class_path)+str(leaf_name)+'.java" title="subclass '+str(leaf_name)+'">|'+str(lvl_indent)+'> '+str(leaf_name)+str(source_a)+str(docs_a)+'</span>\n'

                                    if sub_classes_count > 0:
                                        result = print_classes_tree(
                                            tree[leaf], result, level+1)

                                    if sub_classes_count > 0:
                                        result += "</details>"
                                return result

                            printClassesResult = str(print_classes_tree(
                                dict(classesTree), printClassesResult, 1))
                            printClassesResult += "</details>\n"

                            # printClassesResult = str(BeautifulSoup(printClassesResult, features="html.parser").prettify())

                            result_markdown += "\n" + printClassesResult + "\n"
                        else:
                            result_markdown += "\n **failed** to detect classes! \n\n"
                            logging.error("parsing of 'get_embedded_classes()' for apk '"+str(
                                apk_file_temp)+"' failed! -> error: result is None!")
                    except Exception as e:
                        result_markdown += "\n **failed** to detect classes! \n\n"
                        logging.error("parsing of 'get_embedded_classes()' for apk '" +
                                      str(apk_file_temp)+"' failed! -> error: "+str(e))

                    # --- end of embedded_classes ---

                    result_markdown += "\n\nThis report was generated on " + str(datetime.now(tzutc()).strftime(
                        "%Y-%m-%d at %H:%M (%Z)")) + " using [`exodus-core`](https://github.com/Exodus-Privacy/exodus-core/).\n"

                    try:
                        # pprint(analysisTemp.signatures[0])

                        try:
                            # list of named tuples -> also see: https://stackoverflow.com/questions/26180528/convert-a-namedtuple-into-a-dictionary
                            trackerSignatures = list(analysis_temp.signatures)
                        except Exception as e:
                            trackerSignatures = []
                            logging.error(
                                "while trying to save tracker signatures -> error: "+str(e))

                        if len(trackerSignatures) > 0:
                            trackerSignaturesRaw = trackerSignatures
                            trackerSignatures = []
                            for trackerSignatureTemp in trackerSignaturesRaw:
                                try:
                                    trackerSignatures.append(
                                        trackerSignatureTemp._asdict())
                                except Exception as e:
                                    logging.error(
                                        "while trying to parse tracker signature '"+str(trackerSignatureTemp)+"' -> error: "+str(e))
                        else:
                            logging.error(
                                "while trying to parse tracker signatures -> error: data length is invalid!")

                        with open(str(Path(working_dir / "tracker-signatures.json").absolute()), "w+", encoding="utf-8") as fh:
                            fh.write(
                                str(json.dumps(trackerSignatures, indent=4)))

                        logging.debug("created tracker signature dump '"+str(Path(working_dir / "tracker-signatures.json").absolute(
                        ))+"' ("+str(Path(working_dir / "tracker-signatures.json").stat().st_size)+") ")

                        result_markdown += "\nThe analysis has been conducted using " + \
                            str(len(analysis_temp.signatures)) + \
                            " tracker signatures by [ExodusPrivacy](https://exodus-privacy.eu.org/)."
                    except Exception as e:
                        logging.error(
                            "while trying to save tracker signatures -> error: "+str(e))

                    try:
                        # pprint(resultDict)
                        with open(str(Path(working_dir / "analysis-result.json").absolute()), "w+", encoding="utf-8") as fh:
                            fh.write(str(json.dumps(result_dict, indent=4)))

                        logging.debug("created report '"+str(Path(working_dir / "analysis-result.json").absolute(
                        ))+"' ("+str(Path(working_dir / "analysis-result.json").stat().st_size)+") ")
                    except Exception as e:
                        logging.error("while trying to save analysis result as json file '"+str(
                            Path(working_dir / "analysis-result.json").absolute())+"' -> error: "+str(e))

                    try:
                        # pprint(resultMarkdown)
                        with open(str(Path(working_dir / "analysis-result.md").absolute()), "w+", encoding="utf-8") as fh:
                            fh.write(str(result_markdown))

                        logging.debug("created report '"+str(Path(working_dir / "analysis-result.md").absolute(
                        ))+"' ("+str(Path(working_dir / "analysis-result.md").stat().st_size)+") ")
                    except Exception as e:
                        logging.error("while trying to save analysis result as markdown file '"+str(
                            Path(working_dir / "analysis-result.md").absolute())+"' -> error: "+str(e))

                    try:
                        indexHtmlReq = requests.get(
                            "https://tinyweatherforecastgermanygroup.gitlab.io/index/index.html", headers=headers, timeout=20)

                        indexHtmlContent = str(indexHtmlReq.text).strip()

                        indexHtmlContent = indexHtmlContent.replace(
                            "Last update of this GitLab Pages page",
                            "Last update of this GitHub Pages page")

                        index_html_soup = BeautifulSoup(
                            indexHtmlContent, features="html.parser")

                        for tagGroup in [index_html_soup.select('#repo-latest-release-container'), index_html_soup.select('#readme-content-container'), index_html_soup.select('#readme-content-container')]:
                            for tag in tagGroup:
                                tag.decompose()

                        indexMarkdownSoup = BeautifulSoup('<div role="document" aria-label="ExodusPrivacy tracker report about TinyWeatherForecastGermany" id="exodus-privacy-report">'+str(
                            markdown.markdown(result_markdown, extensions=['extra', 'sane_lists', TocExtension(baselevel=2, title='Table of contents', anchorlink=True)]))+'</div>', features='html.parser')

                        if len(index_html_soup.select("#repo-metadata-container")) > 0:
                            index_html_soup.select(
                                "#repo-metadata-container")[0].insert_after(indexMarkdownSoup)
                        else:
                            logging.error(
                                " could NOT insert converted markdown markup from report! ")

                        index_html_soup.title.string = "ExodusPrivacy report | Tiny Weather Forecast Germany"

                        if len(list(index_html_soup.select('meta[name="google-site-verification"]'))) > 0:
                            index_html_soup.select(
                                'meta[name="google-site-verification"]')[0].decompose()

                        try:
                            page_timestamp = index_html_soup.select(
                                "#page-timestamp-last-update")
                            if len(page_timestamp) > 0:
                                page_timestamp[0].string = str(datetime.now(
                                    tzutc()).strftime("%Y-%m-%d at %H:%M (%Z)"))
                                page_timestamp[0]["data-timestamp"] = str(
                                    datetime.now(tzutc()).strftime("%Y-%m-%dT%H:%M:000"))
                            else:
                                logging.error(
                                    f"failed to change contents of '#page-timestamp-last-update' in index.html -> error: selector did not match!")
                        except Exception as e:
                            logging.error(
                                f"failed to change contents of '#page-timestamp-last-update' in index.html -> error: {e}")

                        schema_org_meta = ",".join(list(index_html_soup.select(
                            'script[type="application/ld+json"]')[0].contents)).strip()

                        """
                            {
                                "@context": "https://schema.org",
                                "@type": "Organization",
                                "url": "http://www.example.com",
                                "logo": "http://www.example.com/images/logo.png"
                            }
                        """
                        schema_org_meta = "[" + schema_org_meta
                        schema_org_meta += """, {
                            "@context": "https://schema.org",
                            "@type": "BreadcrumbList",
                            "itemListElement": [{
                                "@type": "ListItem",
                                "position": 1,
                                "name": "Index",
                                "item": "https://tinyweatherforecastgermanygroup.gitlab.io/index/"
                            },{
                                "@type": "ListItem",
                                "position": 2,
                                "name": "ExodusPrivacy report",
                                "item": "https://twfgcicdbot.github.io/TinyWeatherForecastGermanyScan/"
                            }]
                        }]

                        """
                        schema_org_meta = regex.sub(
                            r'(?im)[\r\t\n]+', '', schema_org_meta)
                        schema_org_meta = regex.sub(
                            r'(?im)( )*(  ){2}', ' ', schema_org_meta)
                        index_html_soup.select(
                            'script[type="application/ld+json"]')[0].string = schema_org_meta

                        try:
                            if len(list(index_html_soup.select('body script[src*="gitlab"]'))) > 0:
                                for script_tag in index_html_soup.select('body script[src*="gitlab"]'):
                                    script_tag.decompose()
                        except Exception as e:
                            logging.error(
                                f"failed to remove 'script' tags from 'body' -> error: {e}")

                        try:
                            css_links = list(index_html_soup.select(
                                'head link[rel="stylesheet"]'))
                            len_css = len(css_links)
                            logging.debug(
                                f"found {len_css} referenced stylesheets in 'head' -> {css_links} ")

                            for css_index in range(len_css):
                                css_link = css_links[css_index]
                                try:
                                    css_href = str(css_link.get('href'))
                                    if len(css_href.replace('None', '').strip()) > 0:
                                        response = requests.get(
                                            css_href, stream=True, headers=headers, timeout=20)
                                        dl_file = str(css_href.rsplit(
                                            '/', maxsplit=1)[-1])
                                        dl_path = working_dir / dl_file

                                        css_txt = str(response.text)
                                        try:
                                            if css_index == len_css - 1:
                                                css_add = """
                                                #permissions-list,
                                                #permissions-list li {
                                                    max-width: 98%;
                                                }
                                                .permission-title {
                                                    max-width: 98%;
                                                    word-break: break-all;
                                                }

                                                .cert-details {
                                                    max-width: 98%;
                                                }
                                                .cert-details span {
                                                    max-width: 96%;
                                                    word-break: all;
                                                }

                                                .subclass-child {
                                                    padding: 1px;
                                                    display: block;
                                                    margin-left: 13px;
                                                }
                                                """
                                                css_add = regex.sub(
                                                    r'(?im)[\r\t\n]+', '', css_add)
                                                css_add = regex.sub(
                                                    r'(?im)( )*(  ){2}', ' ', css_add)
                                                css_txt += css_add
                                                logging.debug(
                                                    "insert additional css")
                                        except Exception as e:
                                            logging.error(
                                                f"failed to insert additional css -> error: {e}")

                                        with open(str(dl_path.absolute()), 'w+') as fh:
                                            fh.write(css_txt)
                                        del response
                                        logging.debug(
                                            f"completed download of '{dl_path}' ({dl_path.stat().st_size}) ")
                                        css_link['href'] = dl_file
                                    else:
                                        logging.error(
                                            f"failed to download stylesheet '{css_link}' -> error: value of 'href' -> '{css_href}' is invalid!")
                                except Exception as e:
                                    logging.error(
                                        f"failed to download stylesheet '{css_link}' -> error: {e}")
                        except Exception as e:
                            logging.error(
                                f"failed to remove stylesheet 'link' tags from 'head' -> error: {e}")

                        try:
                            toc_js_str = """
    <script>
        try {
            if (document.querySelectorAll(".toc > ul > li").length > 0) {
                document.querySelectorAll(".toc > ul > li").forEach(function(element) {
                    if (element.querySelectorAll("ul > li").length > 0) {
                        tocLinkTemp = element.querySelector("a");
                        tocLinkTemp.title = "click to toggle childrens";
                        tocLinkTemp.setAttribute("aria-roledescription", "click to toggle childrens");
                        tocLinkTemp.addEventListener('click', function(event) {
                            event.preventDefault();
                            console.log(event);
                            event.target.parentElement.querySelectorAll("ul").forEach(function(listchild) {
                                console.log(listchild.style.display);
                                if (listchild.style.display.length > 0) {
                                    listchild.style.display = listchild.style.display === 'none' ? 'block' : 'none';
                                } else {
                                    listchild.style.display = 'block';
                                }
                                console.log(listchild.style.display);
                            })
                        })
                    }
                });
            }
        } catch (error) {
            console.log("ERROR: failed to make level 3 toc entries toggle visibility of children items on click -> error: " + e);
        }
    </script>
                            """

                            toc_js_str = regex.sub(
                                r'(?im)[\r\t\n]+', '', toc_js_str)
                            toc_js_str = regex.sub(
                                r'(?im)( )*(  ){2}', ' ', toc_js_str)
                            toc_js_soup = BeautifulSoup(
                                toc_js_str, features='html.parser')
                            index_html_soup.select(
                                "#page-footer-text")[0].insert_after(toc_js_soup)
                        except Exception as e:
                            logging.error(
                                "failed to add ToC JavaScript code -> error: "+str(e))

                        try:
                            if len(index_html_soup.select("#page-footer-hosting-name")) > 0:
                                index_html_soup.select(
                                    "#page-footer-hosting-name")[0].string = "GitHub Pages"
                            else:
                                logging.warning(
                                    "failed to find '#page-footer-hosting-name' in index.html ")
                        except Exception as e:
                            logging.error(
                                f"failed to change contents of '#page-footer-hosting-name' in index.html -> error: {e}")

                        try:
                            if len(index_html_soup.select("#page-footer-source-code-link")) > 0:
                                index_html_soup.select("#page-footer-source-code-link")[
                                    0]["href"] = "https://github.com/twfgcicdbot/TinyWeatherForecastGermanyScan/tree/gh-pages"
                            else:
                                logging.warning(
                                    "failed to find '#page-footer-source-code-link' in index.html ")
                        except Exception as e:
                            logging.error(
                                f"failed to change contents of '#page-footer-source-code-link' in index.html -> error: {e}")

                        try:
                            if len(index_html_soup.select("#page-footer-repo-license-link")) > 0:
                                index_html_soup.select("#page-footer-repo-license-link")[
                                    0]["href"] = "https://github.com/twfgcicdbot/TinyWeatherForecastGermanyScan/blob/d19eb5eeeda3649ecd93a3b52f018878dd24ec81/LICENSE"
                            else:
                                logging.warning(
                                    "failed to find '#page-footer-repo-license-link' in index.html")
                        except Exception as e:
                            logging.error(
                                f"failed to change contents of '#page-footer-repo-license-link' in index.html -> error: {e}")

                        try:
                            stars_count = index_html_soup.select(
                                "#repo-stars-count")
                            if len(stars_count) > 0:
                                stars_count[0]["href"] = "https://tinyweatherforecastgermanygroup.gitlab.io/index/stargazers.html"
                                stars_count[0]["target"] = "_blank"
                            else:
                                logging.warning(
                                    "failed to find '#repo-stars-count' in index.html")
                        except Exception as e:
                            logging.error(
                                f"failed to change contents of '#repo-stars-count' in index.html -> error: {e}")

                        try:
                            watchers_count = index_html_soup.select(
                                "#repo-watchers-count")
                            if len(watchers_count) > 0:
                                watchers_count[0]["href"] = "https://tinyweatherforecastgermanygroup.gitlab.io/index/watchers.html"
                                watchers_count[0]["target"] = "_blank"
                            else:
                                logging.warning(
                                    "failed to find '#repo-watchers-count' in index.html")
                        except Exception as e:
                            logging.error(
                                f"failed to change contents of '#repo-watchers-count' in index.html -> error: {e}")

                        report_file_html = str(index_html_soup).strip()

                        report_html_file = str(
                            Path(working_dir / "index.html").absolute())
                        try:
                            with open(report_html_file, "w+", encoding="utf-8") as fh:
                                fh.write(htmlmin.minify(report_file_html,
                                                        remove_empty_space=True))
                        except Exception as e:
                            logging.error(
                                f"minification of '{report_html_file}' failed -> error: {e}")
                            with open(report_html_file, "w+", encoding="utf-8") as fh:
                                fh.write(report_file_html)
                    except Exception as e:
                        logging.error(
                            f"while trying to save analysis result as html file -> error: {e}")

                    try:
                        robots_txt = """
User-agent: *
Allow: /

Sitemap: https://twfgcicdbot.github.io/TinyWeatherForecastGermanyScan/sitemap.xml
                        """

                        with open(str(Path(working_dir / "robots.txt").absolute()), "w+", encoding="utf-8") as fh:
                            fh.write(str(robots_txt).strip())
                    except Exception as e:
                        logging.error(
                            f"failed to generate robots.txt -> error: {e}")

                    lastModPageStrSiteMap = ""
                    try:
                        lastModPageStrSiteMap = '<lastmod>' + \
                            str(datetime.now(tzutc()).strftime(
                                "%Y-%m-%dT%H:%M+00:00"))+'</lastmod>'
                    except Exception as e:
                        logging.error(
                            f"failed to generate meta tag 'pubdate' -> error: {e}")

                    try:
                        sitemapXML = """
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:content="http://www.google.com/schemas/sitemap-content/1.0">
 <url>
   <loc>https://twfgcicdbot.github.io/TinyWeatherForecastGermanyScan</loc>
    """+lastModPageStrSiteMap+"""
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
    </url>
</urlset>
                        """
                        with open(str(Path(working_dir / "sitemap.xml").absolute()), "w+", encoding="utf-8") as fh:
                            fh.write(str(sitemapXML).strip())

                    except Exception as e:
                        logging.error(
                            f"while generarting sitemap.xml -> error: {e}")

                except Exception as e:
                    logging.error(
                        f"while processing '{apk_file_temp}' -> error: {e}")
    except Exception as e:
        logging.error(""+str(e))

else:
    logging.error("content of codeberg json response is invalid!")

    try:
        pprint(str(search_cb_req.headers))
        pprint(str(search_cb_req.text))
    except Exception as e:
        logging.error(
            f"failed to print request raw data to console! -> error: {e}")

    sys.exit(1)

print("done")
logging.info("finished execution of main.py")
