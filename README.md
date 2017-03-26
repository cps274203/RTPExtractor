## Requirements
Python 3.5+ with following modules:
* Tornado
* six

OS support:
- Linux,Windows,MacOS

## Logging
All web/operating logs are written to the *logs/server.log*
Additionally each script logs are written to separate file in *logs/processes*. File name format is {script\_name}\_{client\_address}\_{date}\_{time}.log. 

## Testing/demo
Script-server has bundled configs/scripts for testing/demo purposes, which are located in testing folder. You can link/copy testing config files to server config files.
