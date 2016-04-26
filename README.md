Shell Detector
==================
<img src="http://www.emposha.com/wp-content/uploads/2011/07/shelldetect3-300x201.png" width="100" align="left" style="padding-right: 4px;" /> 
Shell Detector – is a application that helps you find and identify php/cgi(perl)/asp/aspx shells. Shell Detector has a “web shells” signature database that helps to identify “web shell” up to 99%.

Shell Detector is released under the MIT License <http://www.opensource.org/licenses/mit-license.php>

More information and support at http://www.shelldetector.com

Special thanks to "JetBrains" for PyCharm licence!

Detection
---------

  Number of known shells: 604

Requirements
---------

  Python 2.x

Usage
-----

    wget https://raw.github.com/emposha/Shell-Detector/master/shelldetect.py
    python shelldetect.py -r True -d ./

Options
-------
 - -d (--directory)   - specify directory to scan
 - -e (--extension)   - specify file extensions that should be scanned, seperate by comma
 - -l (--linenumbers) - show line number where suspicious function used
 - -r (--remote)      - get shells signatures db from github

Changelog
---------

 - 1.1 Full rewrite, preparing for standalone version.

 - 1.0 First version
