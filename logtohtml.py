"""

**title**: TinyWeatherForecastGermany - log to html

**description**: parse python log file debug.log and generate html file with syntax highlighting

**author**: Jean-Luc Tibaux (https://gitlab.com/eUgEntOptIc44)

**license**: GPLv3 (https://github.com/twfgcicdbot/TinyWeatherForecastGermanyScan/blob/d19eb5eeeda3649ecd93a3b52f018878dd24ec81/LICENSE)

**since**: September 2021

**url**: https://twfgcicdbot.github.io/TinyWeatherForecastGermanyScan/debug.html

## Disclaimer

No warranty of any kind provided. Use at your own risk only.
Not meant to be used in commercial or in general critical/productive environments at all.

"""

import logging
import sys
from pathlib import Path

import htmlmin  # html minifier
import regex  # extends feature set of 're' -> regular expressions
from bs4 import BeautifulSoup  # for html parsing

from pygments import highlight  # python code syntax hightlighter
from pygments.formatters import HtmlFormatter
from pygments.lexers import get_lexer_by_name

working_dir = Path("TinyWeatherForecastGermanyScan")
# create directory if not exists
working_dir.mkdir(parents=True, exist_ok=True)

log_p2 = working_dir / "debug2.log"
try:
    logging.basicConfig(
        format="%(asctime)-s %(levelname)s [%(name)s]: %(message)s",
        level=logging.DEBUG,
        handlers=[
            logging.FileHandler(str(log_p2), encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )
except Exception as error_msg:
    logging.error(f"while logger init! -> error: {error_msg}")

log_p1 = working_dir / "debug.log"
try:
    with open(str(log_p1), "r", encoding="utf-8") as file_handle:
        code = str(file_handle.read())
except Exception as error_msg:
    logging.error(f"failed to open '{log_p1.absolute()}' -> error: {error_msg}")
    sys.exit("FATAL ERROR script execution aborted!")

codeLines = str(code).split("\n")
hlLinesIndices = []

for lineIndex in range(len(codeLines)):
    # print(codeLines[lineIndex])
    line_tmp = str(codeLines[lineIndex]).lower()

    if "error:" in line_tmp or "warning:" in line_tmp:
        hlLinesIndices.append(lineIndex + 1)
        logging.debug(f"identified 'error:' match in line #{lineIndex+1}")

# using 'logtalk' as no dedicated python log lexer exists
lexer = get_lexer_by_name("logtalk", stripall=True)
logging.debug("lexer init completed")

formatter = HtmlFormatter(
    linenos=True,
    cssclass="sourcecode",
    full=True,
    style="perldoc",
    title="debug.log | Tiny Weather Forecast Germany",
    lineanchors="debuglog",
    lineseparator="<br>",
    hl_lines=hlLinesIndices,
    wrapcode=True,
)
logging.debug("HtmlFormatter init completed")

result = highlight(code, lexer, formatter)
logging.debug("highlight finished")

# parse html to modify elements
debug_file_soup = BeautifulSoup(str(result), features="html.parser")

for metaTemp in debug_file_soup.select("head > meta"):
    metaTemp.decompose()

head_html = (
    '\n\n<meta http-equiv="content-type" content="text/html; charset=UTF-8" />\n'
    '<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
    '<meta name="robots" content="noindex, nofollow">'
)

head_html += """\n
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

debug_file_soup.title.insert_after(
    BeautifulSoup(head_html, features="html.parser")
)  # parse html to modify elements

logging.debug("added additional 'meta' tags")

first_css_el = debug_file_soup.select("head style")
if len(first_css_el) > 0:
    first_css = first_css_el[0]
    css_txt = str(first_css.text)
    first_css.decompose()

css_str = """
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
    * {
        max-width: 98%!important;
        color: #000000!important;
    }
    body {
        filter: invert(0);
        background: transparent;
    }
    code, pre {
        word-break: break-word;
        word-wrap: break-word;
    }
}
"""

css_txt += css_str
css_txt = regex.sub(r"(?im)[\r\t\n]+", "", css_txt)
css_txt = regex.sub(r"(?im)( )*(  ){2}", " ", css_txt)
css_txt = regex.sub(r"(?m)\/\*([^\*]+)\*\/", "", css_txt)

# parse html to modify elements
debug_file_soup.head.append(
    BeautifulSoup(f'<style type="text/css">{css_txt}</style>', features="html.parser")
)

logging.debug("added additional 'css' tag ")

debug_html_file = str(Path(working_dir / "debug.html").absolute())
try:
    with open(debug_html_file, "w+", encoding="utf-8") as file_handle:
        file_handle.write(
            htmlmin.minify(
                str(debug_file_soup), remove_empty_space=True, remove_comments=True
            )
        )
except Exception as error_msg:
    logging.error(f"minification of '{debug_html_file}' failed -> error: {error_msg}")
    with open(debug_html_file, "w+", encoding="utf-8") as file_handle:
        file_handle.write(str(debug_file_soup))

print("done")
logging.info("finished execution of logtohtml.py")
