## The p11kmip tool
The p11kmip tool uses slightly modified libkmipclient code from the s390-tools
package as a static library to interface with a KMIP server:
- [https://github.com/ibm-s390-linux/s390-tools/tree/master/libkmipclient](https://github.com/ibm-s390-linux/s390-tools/tree/master/libkmipclient)
- [https://github.com/ibm-s390-linux/s390-tools/tree/master/include/kmipclient](https://github.com/ibm-s390-linux/s390-tools/tree/master/include/kmipclient)

Modifications were done to fit to the OpenCrptoki environment, and to be able to
build the libkmipclient library without support for KMIP over HTTPS, as well as
without support for JSON and XML encoding. The p11kmip tool currently only
uses KMIP TTLV encoding over plain TLS.

The license of the libkmipclient source files were changed from MIT to Common
Public License, version 1.0 (CPL-1.0).
