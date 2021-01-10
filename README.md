Util to check validity, view directory structure and extract stream data from
CFB files. Often extracted streams are not human-readable and need more
processing to be useful.

CFB is a universal file format, used in MSOffice before 2007 (doc, xls, ...) and less widely in Office 2007+ (for example vbaProject.bin is CFB file).

cfb_parser.py [-h] [-s] [-d] [-f] [-v] [-q] [--no-magic] inputfile [inputfile ...]

Positional arguments:
- inputfile   Input file name

Optional arguments:
- -h show this help message and exit
- -s Save objects in file to directory tree
- -d Save all dangling (not connected to directory tree) streams and ministreams
- -f Clean output directory if exists
- -v Be Verbose (use several times to be more verbose)
- -q Be quite, output nothing on errors
- --no-magic Parse file even if magic is wrong
