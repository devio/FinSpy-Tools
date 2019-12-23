
# finspy config extract finspyCfgExtract (c) 2019
# by Thorsten (THS) Schroeder <ths [at] ccc [dot] de>
#
# Extract configuration data from Finspy-APKs for Android. Based on
#   https://github.com/SpiderLabs/malware-analysis/tree/master/Ruby/FinSpy
# and
#   https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/finspy-mobile-configuration-and-insight/
# by
#   Josh Grunzweig
#
# Thank you, Josh!
#
# In contrast to SpiderLabs' version, we are able to extract data from recent
# variations of finspy, as we use a different approach to spot the hidden data
# in CDS sections.
#
# ---------------------------------------------------------------------------------------------------------
#
#   BSD 3-Clause License (modified)
#
#   Copyright (c) 2019, Chaos Computer Club
#   Author: Thorsten (THS) Schroeder <ths [at] ccc [dot] de>
#   All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#  
#  * Redistributions of source code must retain the above copyright notice, this
#	   list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice,
#	   this list of conditions and the following disclaimer in the documentation
#	   and/or other materials provided with the distribution.
#  * Neither the name of the copyright holder nor the names of its
#	   contributors may be used to endorse or promote products derived from
#	   this software without specific prior written permission.
#
#  * NON-MILITARY-USAGE CLAUSE
#	   Redistribution and use in source and binary form for military use and
#	   military research is not permitted. Infringement of these clauses may
#	   result in publishing the source code of the utilizing applications and
#	   libraries to the public. As this software is developed, tested and
#	   reviewed by *international* volunteers, this clause shall not be refused
#	   due to the matter of *national* security concerns.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# ---------------------------------------------------------------------------------------------------------

import sys
import struct
import base64

CDS_START = 0x02014b50;  # {'P', 'K', 0x01, 0x02}


def extract(data):
    i = 0
    b64data = ""
    apklen = len(data)
    stop = False


    while i < apklen:
        tmp = data[i:i + 4]
				
        if int.from_bytes(tmp, byteorder='little') == CDS_START:
            # print("[d] found PK CDS header at {}!".format(i))

            tmp = data[i:i + 46]

						# parse pkzip cds section header
            hdrid, \
            version, host_os, min_version, target_os, \
            gp_flags, compression_method, \
            file_time, file_crc, file_size_compressed, file_size_uncompressed, \
            filename_len, extrafield_len, comment_len, disk_number, \
            hidden_data, \
            local_hdr_offset = struct.unpack("<I4c2H4I4H6sI", tmp)

            internal_bm, external_bm = struct.unpack("<HI", hidden_data)
            
						# We should use better/additional methods to detect a finspy related CDS section. 
						# This one involves quite a few false positives.
            if (internal_bm & 0xfffa) > 0:
                print("[d] internal_bm = {0:x}".format(internal_bm))
                print("[d] external_bm = {0:x}".format(external_bm))
                print("[*] found hidden data in CDS at offset {0:x}: {1}".format(i, hidden_data))

                try:
                    idx = 0
                    
                    if not stop and hidden_data.decode('ascii').isprintable():
                        # print(hidden_data.decode('utf-8'))
                        b64data = b64data + hidden_data.decode('ascii')
                        print("[d] appended {}".format(hidden_data.decode('ascii')))
                    else:
                        print("[!] unable to decode hidden_data properly: {}".format(hidden_data))
                        # append anyway...
                        
                        tmp = ""
                        
                        for c in hidden_data.decode('ascii'):
                            if c.isprintable():
                                idx = idx + 1
                            elif idx != 0 and len(b64data) == 0:
                                raise NameError('Illegal finspy hidden data @ b64data index {}.'.format(len(b64data)))
                            elif idx == 0:
                                raise NameError('Illegal finspy hidden data @ b64data index {}.'.format(len(b64data)))
                            elif not stop and len(b64data) != 0:
                                stop = True
                                b64data = b64data + tmp
                                raise NameError('Illegal finspy hidden data @ b64data index {}.'.format(len(b64data)))
                                
                            tmp = tmp + c

                        if not stop:
                            b64data = b64data + tmp
                        
                except Exception as e:
                    pass

        i = i + 1

    print("[d] read {} bytes of base64 encoded hidden data: {}".format(len(b64data), b64data))
    rawdata = base64.b64decode(b64data)

    return rawdata


def main(ac, av):
    if ac < 2:
        print("[!] usage: {} <apk file>".format(av[0]))
        return

    with open(av[1], "rb") as apkfile:
        apkdata = apkfile.read()

    resultcfg = extract(apkdata)

    with open(av[1] + ".cfg", "wb") as cfgfile:
        cfgfile.write(resultcfg)

    return


if __name__ == '__main__':
    main(len(sys.argv), sys.argv)
