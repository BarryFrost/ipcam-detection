# -*- coding: utf-8 -*-
"""
Created on Tue Oct  6 18:07:06 2020

@author: islab
"""

import pydivert
import zlib
from Crypto.Cipher import AES

key = b'0123456789123456'
Compress = False
RequestCompress = False
'''使用 port = 80 可能導致非目標封包，也就是http tcp以外的封包被加密導致溝通失效，目前的推測
    因此改使用port = 8888 可以將範圍限制在正常的http tcp 封包(尚未測試)
    
    圖片加密與壓縮後無法正常顯示
    '''
with pydivert.WinDivert("tcp.DstPort==8888 or tcp.SrcPort==8888") as w:
    for packet in w:      # w is  container
        p = packet.payload
        cipher = AES.new(key, AES.MODE_EAX)
        if packet.src_port == 8888:    #response to encrypt
            if len(p) > 0:
                print('**********Response payload*************')
                if packet.ipv4.packet_len >= 1484:
                    print('packet may be over MTU=1500, compressing....')
                    p = zlib.compress(p)
                    Compress = True
                    print(len(p))
                ct = cipher.encrypt(p)
                data = ct + cipher.nonce
                if Compress:
                    data = b'zip' + data
                    Compress = False
                packet.payload = data
                print(len(packet.payload))
                print('**********Response end*************')
        elif packet.dst_port ==8888:   #request to decrypt
            if len(p) > 0:
                print("-----------Request Start----------")    
                if p[:3] == b'zip':
                    print('compress prefix founded, decompressing...')
                    p = p[3:]
                    RequestCompress = True
                nonce = p[-16:]
                print(len(p))
                ct = p[:-16]
                print("encrypted request")
                print(packet.payload)
                print("-----------payload decrypted----------")                   
                cipher = AES.new(key, AES.MODE_EAX, nonce)
                pt = cipher.decrypt(ct)
                if RequestCompress:
                    pt = zlib.decompress(pt)
                    RequestCompress = False
                packet.payload = pt
                print(packet.payload)
                print("-----------Request End----------")    
        w.send(packet)