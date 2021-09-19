"""

**title**: TinyWeatherForecastGermany - log to html

**description**: parse python log file debug.log and generate html file with syntax highlighting

**author**: Jean-Luc Tibaux (https://gitlab.com/eUgEntOptIc44)

**license**: GPLv3 (https://github.com/twfgcicdbot/TinyWeatherForecastGermanyScan/blob/d19eb5eeeda3649ecd93a3b52f018878dd24ec81/LICENSE)

**since**: September 2021

**url**: https://twfgcicdbot.github.io/TinyWeatherForecastGermanyScan/debug.html

## Disclaimer

No warranty or guarantee of any kind provided. Use at your own risk.
Not meant to be used in commercial or in general critical/productive environments at all.

"""

import logging
from pathlib import Path
import sys

from bs4 import BeautifulSoup # for html parsing
import htmlmin # html minifier

from pygments import highlight # python code syntax hightlighter
from pygments.lexers import get_lexer_by_name
from pygments.formatters import HtmlFormatter

workingDir = Path("TinyWeatherForecastGermanyScan")

workingDir.mkdir(parents=True, exist_ok=True) # create directory if not exists

try:
    logging.basicConfig(format=u'%(asctime)-s %(levelname)s [%(name)s]: %(message)s',
        level=logging.DEBUG,
        handlers=[
            logging.FileHandler(str(Path(workingDir / "debug2.log").absolute()), encoding="utf-8"),
            logging.StreamHandler()
    ])
except Exception as e:
    logging.error("while logger init! -> error: "+str(e))

try:
    with open(str(Path(workingDir / "debug.log").absolute()), "r", encoding="utf-8") as fh:
        code = str(fh.read())
except Exception as e:
    logging.error("failed to open 'debug.log' -> error: "+str(e))
    sys.exit("FATAL ERROR script execution aborted!")

codeLines = str(code).split("\n")
hlLinesIndices = []

for lineIndex in range(len(codeLines)):
    #print(codeLines[lineIndex])
    lineTemp = str(codeLines[lineIndex]).lower()

    if "error:" in lineTemp or "warning:" in lineTemp:
        hlLinesIndices.append(lineIndex+1)
        logging.debug("identified 'error:' match in line #"+str(lineIndex+1)+" ")

lexer = get_lexer_by_name("logtalk", stripall=True) # using 'logtalk' as there's no dedicated python log lexer
logging.debug("lexer init completed")

formatter = HtmlFormatter(linenos=True, cssclass="sourcecode", full=True, style="perldoc", title="debug.log | Tiny Weather Forecast Germany", lineanchors="debuglog", lineseparator="<br>", hl_lines=hlLinesIndices, wrapcode=True)
logging.debug("HtmlFormatter init completed")

result = highlight(code, lexer, formatter)
logging.debug("highlight finished")

debugFileSoup = BeautifulSoup(str(result), features='html.parser') # parse html to modify elements

for metaTemp in debugFileSoup.select('head > meta'):
    metaTemp.decompose()

headHtml = '\n\n<meta http-equiv="content-type" content="text/html; charset=UTF-8" />\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1.0">\n<meta name="robots" content="noindex, nofollow">'

headHtml += """\n
<link rel="apple-touch-icon" sizes="180x180" href="images/apple-touch-icon.png">
<link rel="icon" type="image/png" sizes="32x32" href="images/favicon-32x32.png">
<link rel="icon" type="image/png" sizes="16x16" href="images/favicon-16x16.png">
<link rel="manifest" href="images/site.webmanifest">
<link rel="mask-icon" href="images/safari-pinned-tab.svg" color="#293235">
<link rel="shortcut icon" href="images/favicon.ico">
<meta name="apple-mobile-web-app-title" content="Tiny Weather Forecast Germany">
<meta name="application-name" content="Tiny Weather Forecast Germany">
<meta name="msapplication-TileColor" content="#293235">
<meta name="msapplication-config" content="images/browserconfig.xml">
<meta name="theme-color" content="#293235">
<meta name="description" content="Tiny Weather Forecast Germany - android app using open weather data by DWD">
<meta name="keywords" content="DWD, Deutscher Wetterdienst, android, app, open source, weather, wetter, rainradar, regenradar, map, charts, open data, germany, deutschland, allemagne, duitsland, météo">
<meta name="thumbnail" content="images/icon.png">
"""

debugFileSoup.title.insert_after(BeautifulSoup(headHtml, features='html.parser')) # parse html to modify elements

logging.debug("added additional 'meta' tags ")

cssStr = """
<style type="text/css">
/*
    dark mode -> added by @eugenoptic44
*/
@media (prefers-color-scheme: dark) {
    body {
        filter: invert(1);
        background: #0c0d17;
    }
}
@media print {
    body {
        filter: invert(0);
        background: transparent;
    }
}
</style>
"""

debugFileSoup.select("head style")[0].insert_after(BeautifulSoup(cssStr, features='html.parser')) # parse html to modify elements

logging.debug("added additional 'css' tag ")

debugHtmlFile = str(Path(workingDir / "debug.html").absolute())
try:
    with open(debugHtmlFile, "w+", encoding="utf-8") as fh:
        fh.write(htmlmin.minify(str(debugFileSoup), remove_empty_space=True, remove_comments=True))
except Exception as e:
    logging.error("minification of '"+debugHtmlFile+"' failed -> error: "+str(e))
    with open(debugHtmlFile, "w+", encoding="utf-8") as fh:
        fh.write(str(debugFileSoup))

print("done")
logging.info("finished execution of logtohtml.py")