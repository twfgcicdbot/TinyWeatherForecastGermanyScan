"""
WIP: androguard additional information about apk

"""

from collections import defaultdict
from pathlib import Path
from pprint import pprint
import json

from androguard.misc import AnalyzeAPK

from exodus_core.analysis.static_analysis import StaticAnalysis
from exodus_core.analysis.apk_signature import ApkSignature


apkFileTemp = Path("TinyWeatherForecastGermanyScan/TinyWeatherForecastGermany-build031-version_0.57.3_20211028.apk")

a, d, dx = AnalyzeAPK(str(apkFileTemp.absolute()))

#pprint(a.get_permissions())
#pprint(a.get_activities())

#for methodTemp in list(dx.get_methods()):
#    print(methodTemp.name + " -> " + methodTemp.descriptor)
#for classTemp in list(dx.get_classes()):
#    print(str(classTemp.name).strip("L").strip(";"))

# based on: https://gist.github.com/hrldcpr/2012250
def tree(): return defaultdict(tree)

def addLeafs(t, List):
  for node in List:
    t = t[node]

classesTree = tree()

analysisTemp = StaticAnalysis(str(apkFileTemp.absolute())) # init ExodusPrivacy StaticAnalysis for 'apkFileTemp'
embeddedClasses = analysisTemp.get_embedded_classes()

for embeddedClassTemp in embeddedClasses:
    try:
        classPartsTemp = list(embeddedClassTemp.split("/"))
        addLeafs(classesTree, classPartsTemp)
    except Exception as e:
        print("ERROR:" + str(e))

pprint(classesTree)

with open(str(Path("test.json").absolute()), "w+", encoding="utf-8") as fh:
    fh.write(str(json.dumps(dict(classesTree))))

def printClassesTree(tree):
    tree = dict(tree)
    result = "<details><summary>"+str(dict(dict(tree)[list(tree)[0]]))+"</summary>"
    #if len(list(list(tree)[1])) > 0:
    #    printClassesTree(list(tree)[1])
    result += "</details>"
    return result

pprint(printClassesTree(classesTree))

#pprint(print_blockdiag(dict(classesTree)))