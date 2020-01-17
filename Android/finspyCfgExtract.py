
# finspy config extract (c) 2019
# by Thorsten (THS) Schroeder <ths [at] ccc [dot] de>
#
# Extract configuration data from Finspy-APKs for Android. Based on
#   https://github.com/SpiderLabs/malware-analysis/tree/master/Ruby/FinSpy
# and
#   https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/finspy-mobile-configuration-and-insight/
# by
#   Josh Grunzweig
#
# Thank you!
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
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are met:
#   * Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#   * Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#
#   this software without specific prior written permission.
#   * NON-MILITARY-USAGE CLAUSE
#    Redistribution and use in source and binary form for military use and
#    military research is not permitted. Infringement of these clauses may
#    result in publishing the source code of the utilizing applications and
#    libraries to the public. As this software is developed, tested and
#    reviewed by *international* volunteers, this clause shall not be refused
#    due to the matter of *national* security concerns.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
#   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#   CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
import sys
import struct
import base64

CDS_START = 0x02014b50;  # {'P', 'K', 0x01, 0x02}


def extract(data):
    i = 0
    b64data = ""
    apklen = len(data)
    s=0
    errors = 0

    while i < apklen:
        tmp = data[i:i + 4]

        if int.from_bytes(tmp, byteorder='little') == CDS_START:
            # print("[d] found PK CDS header at {}!".format(i))

            tmp = data[i:i + 46]

            try:
                id, \
                version, host_os, min_version, target_os, \
                gp_flags, compression_method, \
                file_time, file_crc, file_size_compressed, file_size_uncompressed, \
                filename_len, extrafield_len, comment_len, disk_number, \
                hidden_data, \
                local_hdr_offset = struct.unpack("<I4c2H4I4H6sI", tmp)
                internal_bm, external_bm = struct.unpack("<HI", hidden_data)
            except Exception as e:
                print("[e] Error unpacking data from CDS: {}".format(e))
                sys.exit(1)

            if (internal_bm & 0xfffa) > 0:
                # print("[d] internal_bm = {0:x}".format(internal_bm))
                # print("[d] external_bm = {0:x}".format(external_bm))
                print("[*] found hidden data in CDS at offset {0:x}: {1}".format(i, hidden_data))

                try:

                    if hidden_data.decode('ascii').isprintable():
                        #print(hidden_data)
                        b64data = b64data + hidden_data.decode('ascii')
                        s += 1
                    else:
                        print("[!] unable to decode hidden_data properly: {}".format(hidden_data))
                        
                        if errors > 10:
                            print("[!] Too many decoding errors, probably false positive.")
                            sys.exit(1)

                        errors += 1
                        # append anyway, if not at the beginning...
                        if s > 0:
                            b64data = b64data + hidden_data.decode('ascii')

                except Exception as e:
                    print("[e] caught exception while decoding data: {}".format(e))
                    # raise e
                    pass

        i = i + 1

    print("[d] read {} bytes of base64 encoded hidden data: {}".format(len(b64data), b64data))

    rawdata = None

    try:
        rawdata = base64.b64decode(b64data)
    except Exception as e:
        print("[e] could not decode base64-data: ", e)
        pass

    return [rawdata, b64data]


def main(ac, av):
    if ac < 2:
        print("[!] usage: {} <apk file>".format(av[0]))
        return

    print("[+] processing {}".format(av[1]))

    with open(av[1], "rb") as apkfile:
        apkdata = apkfile.read()

    [resultcfg, b64data] = extract(apkdata)

    if resultcfg:
        with open(av[1] + ".cfg", "wb") as cfgfile:
            cfgfile.write(resultcfg)

    print("saving b64 data: {}".format(b64data))

    with open(av[1] + ".b64", "wb") as b64file:
        b64file.write(b64data.encode())

    print("[-] -----------------------------------------------------------")

    return


if __name__ == '__main__':
    main(len(sys.argv), sys.argv)
