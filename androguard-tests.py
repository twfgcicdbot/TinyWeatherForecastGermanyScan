"""
WIP: androguard additional information about apk

"""

from pprint import pprint

from androguard.misc import AnalyzeAPK

a, d, dx = AnalyzeAPK("TinyWeatherForecastGermanyScan/TinyWeatherForecastGermany-build031-version_0.57.3_20211028.apk")

#pprint(a.get_permissions())

#pprint(a.get_activities())

#for methodTemp in list(dx.get_methods()):
#    print(methodTemp.name + " -> " + methodTemp.descriptor)

for classTemp in list(dx.get_classes()):
    print(classTemp.name)