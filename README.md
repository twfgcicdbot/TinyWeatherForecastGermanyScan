# TinyWeatherForecastGermanyScan

[![exodus-privacy scan](https://img.shields.io/github/workflow/status/twfgcicdbot/TinyWeatherForecastGermanyScan/exodus-privacy%20scan?label=exodus-privacy%20scan&logo=github&style=for-the-badge)](https://github.com/twfgcicdbot/TinyWeatherForecastGermanyScan/actions/workflows/exodusscan.yml) [![github pages page](https://img.shields.io/badge/-github%20pages-green?style=for-the-badge&logo=github)](https://twfgcicdbot.github.io/TinyWeatherForecastGermanyScan/index.html) [![F-Droid Store release version](https://img.shields.io/f-droid/v/de.kaffeemitkoffein.tinyweatherforecastgermany?color=%23efbb24&logo=fdroid&style=for-the-badge)](https://f-droid.org/packages/de.kaffeemitkoffein.tinyweatherforecastgermany) [![code license](https://img.shields.io/github/license/twfgcicdbot/TinyWeatherForecastGermanyMirror?style=for-the-badge&logo=github)](https://github.com/twfgcicdbot/TinyWeatherForecastGermanyMirror/blob/master/COPYING) 

tl;dr -> scan code of [**TinyWeatherForecastGermany**](https://codeberg.org/Starfish/TinyWeatherForecastGermany) (TWFG) for tracker signatures provided by [**ExodusPrivacy**](https://exodus-privacy.eu.org/en/) using the python module [exodus-core](https://github.com/Exodus-Privacy/exodus-core/)

[TinyWeatherForecastGermany](https://tinyweatherforecastgermanygroup.gitlab.io/index/) is an android open source weather app focused on Germany developped by Pawel Dube ([@Starfish](https://codeberg.org/Starfish)) using [open data](https://opendata.dwd.de/) provided by Deutscher Wetterdienst (DWD).

The DWD is Germany's **national weather agency** (similiar to **N**ational **O**ceanic **a**nd **A**tmospheric **A**dministration ([NOAA](https://www.noaa.gov/about-our-agency)) in the US).

***Note**: 'TWFG' is an unofficial abbreviation for **T**iny **W**eather **F**orecast **G**ermany.*

## Purpose -> *Why?*

*The non-profit running ExodusPrivacy provides reports itself so ... why wasting resources when generating them on your own?*

At the time of writing (Mid-August 2021) ExodusPrivacy [only allows](https://reports.exodus-privacy.eu.org/de/analysis/submit/) the submission of apps retrieved directly either from Google Play Store or the open source F-Droid app store. But uploading apk files is not possible afaik. Waiting for the update approval process after releasing apps needs patience as (to my personal understanding) it needs interactions of human beings. So that's why I (*Jean-Luc Tibaux* -> [*@eUgEntOptIc44*](https://codeberg.org/eUgEntOptIc44)) setup [my own](https://twfgcicdbot.github.io/TinyWeatherForecastGermanyScan/) solution to scan the apk release artifacts of TWFG.

To scan apks on your android mobile on your own please see either the official ExodusPrivacy app or [ClassyShark3xodus](https://bitbucket.org/oF2pks/fdroid-classyshark3xodus/src/master/ClassySharkAndroid/). The latter works 100% offline.

## Generated reports

data formats:

* **HTML** as a [GitHub Pages page](https://twfgcicdbot.github.io/TinyWeatherForecastGermanyScan/) -> see [`index.html`](https://twfgcicdbot.github.io/TinyWeatherForecastGermanyScan/index.html)

* **Markdown** see [`analysis-result.md`](https://twfgcicdbot.github.io/TinyWeatherForecastGermanyScan/analysis-result.md)

* **JSON** see [`analysis-result.json`](https://twfgcicdbot.github.io/TinyWeatherForecastGermanyScan/analysis-result.json)

## License and Copyright

This repository is licensed under **GPLv3** see [`LICENSE`](https://github.com/twfgcicdbot/TinyWeatherForecastGermanyScan/blob/bb7593cd5436a1be6495c068a3557ca4e4bf646f/LICENSE) for details. Please also see the legal terms noted inline in the code base. The author highly encourages everyone reading this to get in touch **before** using any of the contents of this repository for **commercial or by any means critical applications**.

**Copyright** of the *main* project -> **Tiny Weather Forecast Germany** -> Pawel Dube ([@Starfish](https://codeberg.org/Starfish))

The CI/CD script producing the reports displayed here is a ['GitHub action workflow'](https://github.com/twfgcicdbot/TinyWeatherForecastGermanyScan/actions/workflows/exodusscan.yml) created by Jean-Luc Tibaux (->[eUgEntOptIc44](https://gitlab.com/eUgEntOptIc44)).
Feel free to use it as a inspiration for your own projects. I'd be very grateful if this was helpful to you. Please let me know if so.

Please be aware that the code used here is by no means production-ready. Before using even parts of this in professional/commercial environments please double check against local laws and regulations that might apply. In general your mileage might significantly vary. Use only at your own risk. No guarantee or waranty of any kind provided.

Please also see [this GitLab Pages page](https://tinyweatherforecastgermanygroup.gitlab.io/index/) containing references to all linked resources of [TinyWeatherForecastGermany](https://tinyweatherforecastgermanygroup.gitlab.io/index/).

This project is **not affialited** with any of the following organizations: ClassyShark3xodus, Codeberg, the DWD, ExodusPrivacy, Google, GitLab or GitHub or related individuals in any way.

## Contributing

* All contributions to **Tiny Weather Forecast Germany** are managed at the ['main'](https://codeberg.org/Starfish/TinyWeatherForecastGermany) code repository at [codeberg.org](https://codeberg.org/Starfish/TinyWeatherForecastGermany)
* [**Translations**](https://weblate.bubu1.eu/engage/tiny-weather-forecast-germany/) are managed at the [**weblate** instance](https://weblate.bubu1.eu/projects/tiny-weather-forecast-germany/) provided by Marcus Hoffmann (@Bubu). 
* Feel free to contribute to this script by opening issues and/or merge requests.
* Please also see the automatically generated *javadoc* **code documentation** of Tiny Weather Forecast Germany [at GitLab](https://gitlab.com/tinyweatherforecastgermanygroup/twfg-javadoc).
* For cybersec, privacy and/or copyright related issues regarding this repository please directly contact the maintainer [**Jean-Luc Tibaux**](https://codeberg.org/eUgEntOptIc44)
