# encoding: utf-8
"""
 Shell Detector  v1.0 
 Shell Detector is released under the MIT License <http://www.opensource.org/licenses/mit-license.php>

 Special thanks to JetBRAINS for PyCharm license

 https://github.com/emposha/PHP-Shell-Detector
"""
import threading
import sys
import re
import os
import optparse
import base64
import stat
import fnmatch
import time
from hashlib import md5
import urllib2
import cgi
import datetime


class PhpSerializer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        
    def unserialize(self, s):
        return PhpSerializer._unserialize_var(self, s)[0]

    def _unserialize_var(self, s):
        return (
            {'i': PhpSerializer._unserialize_int
                , 'b': PhpSerializer._unserialize_bool
                , 'd': PhpSerializer._unserialize_double
                , 'n': PhpSerializer._unserialize_null
                , 's': PhpSerializer._unserialize_string
                , 'a': PhpSerializer._unserialize_array
            }[s[0].lower()](self, s[2:]))

    def _unserialize_int(self, s):
        x = s.partition(';')
        return (int(x[0]), x[2])

    def _unserialize_bool(self, s):
        x = s.partition(';')
        return (x[0] == '1', x[2])

    def _unserialize_double(self, s):
        x = s.partition(';')
        return (float(x[0]), x[2])

    def _unserialize_null(self, s):
        return (None, s)

    def _unserialize_string(self, s):
        (l, _, s) = s.partition(':')
        return (s[1:int(l) + 1], s[int(l) + 3:])

    def _unserialize_array(self, s):
        (l, _, s) = s.partition(':')
        a, k, s = {}, None, s[1:]

        for i in range(0, int(l) * 2):
            (v, s) = PhpSerializer._unserialize_var(self, s)

            if k:
                a[k] = v
                k = None
            else:
                k = v

        return (a, s[1:])


class ShellDetector(threading.Thread):
    _extension = ["php", "asp", "txt"]

    #settings: show command line message only (no html report will be created)
    _command_line = True
    #settings: show line number where suspicious function used
    _showlinenumbers = True
    #settings: used with access time & modified time
    _dateformat = "H:i:s d/m/Y"
    #settings: scan specific directory
    _directory = '.'
    #settings: scan hidden files & directories
    _scan_hidden = True
    #settings: used with is_cron(true) file format for report file
    _report_format = 'shelldetector_%d-%m-%Y_%H%M%S.html'
    #settings: get shells signatures db by remote
    _remotefingerprint = False

    #default ouput
    _output = ""
    _files = []
    _badfiles = []
    _fingerprints = []

    #system: title
    _title = 'Shell Detector'
    #system: version of shell detector
    _version = '1.1'
    #system: regex for detect Suspicious behavior
    _regex = r"(?si)(preg_replace.*\/e|`.*?\$.*?`|\bpassthru\b|\bshell_exec\b|\bexec\b|\bbase64_decode\b|\beval\b|\bsystem\b|\bproc_open\b|\bpopen\b|\bcurl_exec\b|\bcurl_multi_exec\b|\bparse_ini_file\b|\bshow_source\b)"

    def __init__(self, options):
        threading.Thread.__init__(self)
        #set arguments
        if options.extension is not None:
            self._extension = options.extension.split(',')

        self._showlinenumbers = options.linenumbers

        if options.directory is not None:
            self._directory = options.directory

        """if options.dateformat is not None:
            self._dateformat = options.dateformat

        if options.format is not None:
            self._report_format = options.format"""

        self._remotefingerprint = options.remote.lower() in ("yes", "true", "t", "1")

    def remote(self):
        if self._remotefingerprint is True:
            self.alert('Please note we are using remote shell database', 'yellow')
            url = 'https://raw.github.com/emposha/PHP-Shell-Detector/master/shelldetect.db'
            self._fingerprints = urllib2.urlopen(url).read()
            try:
                self._fingerprints = base64.decodestring(bytes(self._fingerprints))
                serial = PhpSerializer()
                self._fingerprints = serial.unserialize(str(self._fingerprints))
            except IOError as e:
                print("({})".format(e))
        else:
            if os.path.isfile("shelldetect.db"):
                try:
                    self._fingerprints = base64.decodestring(str(open('shelldetect.db', 'r').read()))
                    serial = PhpSerializer()
                    self._fingerprints = serial.unserialize(str(self._fingerprints))
                except IOError as e:
                    print("({})".format(e))

    def start(self):
        self.header()

        #start
        self.remote()
        self.version()
        self.filescan()
        self.anaylize()
        #end

        self.footer()
        return None

    def anaylize(self):
        _counter = 0
        _regex = re.compile(self._regex)
        for _filename in self._files:
            _content = open(_filename, 'rt', -1).read()
            _filename = re.sub('.#', '', _filename)
            _match = _regex.findall(_content)
            if _match:
                self.getfileinfo(_filename)
                if self._showlinenumbers is True:
                    _lines = _content.split("\n")
                    _linecounter = 1
                    for _line in _lines:
                        _match_line = _regex.findall(_line)
                        if _match_line:
                            self.alert('   Suspicious function used: ' + _match_line.__str__() + '(line: ' + str( _linecounter) + ')')
                        _linecounter += 1
                else:
                    self.alert('   Suspicious functions used: ' + _match.__str__())
                _counter += 1
            self.fingerprint(_filename, _content)
        self.alert('=======================================================', 'yellow')
        self.alert('Status: ' + str(_counter) + ' suspicious files and ' + str(len(self._badfiles)) + ' shells', 'red')

    def _get_precomputed_fingerprints(self):
        if not hasattr(self, '_precomputed_fingerprints'):
            self._precomputed_fingerprints = []
            for fingerprint, shellname in self._fingerprints.iteritems():
                if fingerprint == "version":
                    continue
                if 'bb:' in fingerprint:
                    fingerprint = base64.decodestring(bytes(fingerprint.replace('bb:', '')))
                self._precomputed_fingerprints.append((re.compile(re.escape(fingerprint)), shellname))
        return self._precomputed_fingerprints
    
    def fingerprint(self, _filename, _content):
        for _regex, shellname in self._get_precomputed_fingerprints():
            _match = _regex.findall(base64.b64encode(_content))
            if _match:
                self._badfiles.append([_filename])
                _regex_shell = re.compile('^(.+?)\[(.+?)\]\[(.+?)\]\[(.+?)\]')
                _match_shell = list(_regex_shell.findall(shellname)[0])
                _shell_note = ''
                if _match_shell[2] == 1:
                    _shell_note = 'please note it`s a malicious file not a shell'
                elif _match_shell[2] == 2:
                    _shell_note = 'please note potentially dangerous file (legit file but may be used by hackers)'
                _shellflag = _match_shell[0] + '(' + _match_shell[3] + ')'
                self.alert('   Fingerprint: Positive, it`s a ' + str(_shellflag) + ' ' + _shell_note, 'red')

    def unpack(self):
        """ Need to work on it"""


    def getfileinfo(self, _file):
        (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime) = os.stat(_file)
        self.alert('')
        self.alert('=======================================================', 'yellow')
        self.alert('')
        self.alert('   Suspicious behavior found in: ' + _file)
        self.alert('   Full path:     ' + os.path.abspath(_file))
        self.alert('   Owner:         ' + str(uid) + ':' + str(gid))
        self.alert('   Permission:    ' + oct(mode)[-3:])
        self.alert('   Last accessed: ' + time.ctime(atime))
        self.alert('   Last modified: ' + time.ctime(mtime))
        self.alert('   Filesize:      ' + self.sizeof_fmt(size))
        self.alert('')

    def sizeof_fmt(self, num):
        for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
            if num < 1024.0:
                return "%3.1f %s" % (num, x)
            num /= 1024.0

    def version(self):
        try:
            _version = self._fingerprints['version']
        except ValueError:
            _version = 0
        try:
            _server_version = urllib2.urlopen('https://raw.github.com/emposha/PHP-Shell-Detector/master/version/db').read()
        except ValueError:
            _server_version = 0

        if _server_version == 0:
            self.alert( 'Cant connect to server! Version check failed!', 'red')
        else:
            if _server_version < _version:
                self.alert('New version of shells signature database found. Please update!', 'red')

        try:
            _app_server_version = urllib2.urlopen('https://raw.github.com/emposha/Shell-Detector/master/version/app').read()
        except urllib2.HTTPError:
            _app_server_version = 0

        if _app_server_version == 0:
            self.alert('Cant connect to server! Application version check failed!', 'red')
        else:
            if _server_version < _version:
                self.alert('New version of application found. Please update!', 'red')

    def filescan(self):
        self.alert('Starting file scanner, please be patient file scanning can take some time.')
        self.alert('Number of known shells in database is: ' + str(len(self._fingerprints)))
        self.listdir()
        self.alert('File scan done, we have: ' + str(len(self._files)) + ' files to analyze')

    def listdir(self):
        for root, dirnames, filenames in os.walk(self._directory):
            for extension in self._extension:
                for filename in fnmatch.filter(filenames, '*.' + extension):
                    self._files.append(os.path.join(root, filename))
        return None

    def header(self):
        self.alert('*************************************************************************************************')
        self.alert('*                                                                                               *')
        self.alert('*                                Welcome to Shell Detector Tool 1.1                             *')
        self.alert('*                                More information can be found here                             *')
        self.alert('*                                   http://www.shelldetector.com                                *')
        self.alert('*                                                                                               *')
        self.alert('*************************************************************************************************')
        self.alert('')

    def footer(self):
        self.alert('')
        self.alert('*************************************************************************************************', 'green')
        self.alert('*                                                                                               *', 'green')
        self.alert('*                  In case you need help email us at support@shelldetector.com                  *', 'green')
        self.alert('*                                                                                               *', 'green')
        self.alert('*************************************************************************************************', 'green')
        self.alert('')

    def alert(self, _content, _color='', _class='info', _html=False, _flag=False):
        _color_result = {
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'purple': '\033[95m',
            'blue': '\033[94m',
            '': ''
        }[_color]

        if self.supports_color() is True:
            print _color_result + _content + '\033[0m'
        else:
            print _content

        if _flag is True:
            self.output(_content, _class, _html)

    def supports_color(self):
        """
        --- Taken from Django ---
        Returns True if the running system's terminal supports color, and False
        otherwise.
        """
        plat = sys.platform
        supported_platform = plat != 'Pocket PC' and (plat != 'win32' or
                                                      'ANSICON' in os.environ)
        # isatty is not always implemented, #6223.
        is_a_tty = hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
        if not supported_platform or not is_a_tty:
            return False
        return True

    def output(self, _content, _class='info', _html=True):
        if _html is True:
            self._output += '<div class="' + _class + '">' + _content + '</div>'
        else:
            self._output += _content

    def flush(self):
        if self._command_line is False:
            print("Flush")
            filename = datetime.now().strftime(self._report_format)
            file = open(filename, "w", -1, 'utf-8')
            file.write(self._output)

#Start
parser = optparse.OptionParser()
parser.add_option('--extension', '-e', type="string", default="php,txt,asp", help="file extensions that should be scanned, comma separated")
parser.add_option('--linenumbers', '-l', default=True, help="show line number where suspicious function used")
parser.add_option('--directory', '-d', type="string", help="specify directory to scan")
parser.add_option('--remote', '-r', default="False", help="get shells signatures db by remote")
(options, args) = parser.parse_args()

if len(sys.argv) == 1:
    parser.print_usage()
    parser.print_help()
else:
    shell = ShellDetector(options)
    shell.start()
