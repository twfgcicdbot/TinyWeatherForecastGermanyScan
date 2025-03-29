"""
WIP: androguard additional information about apk

"""

import json
from collections import defaultdict
from pathlib import Path
from pprint import pprint

from androguard.misc import AnalyzeAPK
from bs4 import BeautifulSoup
from exodus_core.analysis.apk_signature import ApkSignature
from exodus_core.analysis.static_analysis import StaticAnalysis

apkFileTemp = Path(
    "TinyWeatherForecastGermanyScan/TinyWeatherForecastGermany-build031-version_0.57.3_20211028.apk"
)

a, d, dx = AnalyzeAPK(str(apkFileTemp.absolute()))

# pprint(a.get_permissions())
# pprint(a.get_activities())

# for methodTemp in list(dx.get_methods()):
#    print(methodTemp.name + " -> " + methodTemp.descriptor)
# for classTemp in list(dx.get_classes()):
#    print(str(classTemp.name).strip("L").strip(";"))


# based on: https://gist.github.com/hrldcpr/2012250
def tree():
    return defaultdict(tree)


def addLeafs(t, List):
    for node in List:
        t = t[node]


classesTree = tree()

analysisTemp = StaticAnalysis(
    str(apkFileTemp.absolute())
)  # init ExodusPrivacy StaticAnalysis for 'apkFileTemp'
embeddedClasses = analysisTemp.get_embedded_classes()

for embeddedClassTemp in embeddedClasses:
    try:
        classPartsTemp = list(embeddedClassTemp.split("/"))
        addLeafs(classesTree, classPartsTemp)
    except Exception as error_msg:
        print(f"ERROR: {error_msg}")

# pprint(classesTree)

# with open(str(Path("test.json").absolute()), "w+", encoding="utf-8") as fh:
#    fh.write(str(json.dumps(dict(classesTree), indent=4)))

printClassesResult = (
    "<details><summary>"
    + str(len(list(embeddedClassTemp)))
    + " class(es) detected</summary>\n"
)


def printClassesTree(tree, result, level):
    for leaf in list(tree):
        levelIndent = ""
        for levelIndex in range(0, level):
            levelIndent += "-"

        leafName = str(leaf)
        if level == 1:
            leafName = "<b>" + str(leafName) + "</b>"
        result += (
            "\t<details><summary>|"
            + str(levelIndent)
            + "> "
            + str(leafName)
            + "</summary>\n"
        )

        if len(list(dict(tree[leaf]))) > 0:
            result = printClassesTree(tree[leaf], result, level + 1)
        result += "</details>"
    return result


printClassesResult = str(printClassesTree(dict(classesTree), printClassesResult, 1))
printClassesResult += "</details>\n"

printClassesResult = str(
    BeautifulSoup(printClassesResult, features="html.parser").prettify()
)

with open(str(Path("index.html").absolute()), "w+", encoding="utf-8") as file_handle:
    file_handle.write(printClassesResult)
