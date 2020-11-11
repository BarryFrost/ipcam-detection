# -*- coding: utf-8 -*-
"""
Created on Tue Oct  6 18:07:06 2020

@author: islab
"""

import pydivert
from Crypto.Cipher import AES

key = b'0123456789123456'
'''使用 port = 80 可能導致非目標封包，也就是http tcp以外的封包被加密導致溝通失效，目前的推測
    因此改使用port = 8888 可以將範圍限制在正常的http tcp 封包(尚未測試)'''
with pydivert.WinDivert("tcp.DstPort==8888 or tcp.SrcPort==8888") as w:
    for packet in w:      # w is  container
        p = packet.payload
        cipher = AES.new(key, AES.MODE_EAX)
        if packet.src_port == 8888:    #response to encrypt
            if len(p)>0:
                print(len(p))
                ciphertxt = cipher.encrypt(p)
                print('**********Response*************')
                print(len(packet.payload))
                print('**********EndResponse**********')
                packet.payload = ciphertxt+cipher.nonce
        elif packet.dst_port ==8888:   #request to decrypt
            if len(p)>0:
                #print(p)
                print("-----------stage1----------")    
                nonce = p[-16:]
                p = p[:-16]
                print(len(packet.payload))
                print("-----------stage2-----------")
                cipher = AES.new(key, AES.MODE_EAX, nonce)    
                packet.payload = cipher.decrypt(p)
                print(len(packet.payload))
        w.send(packet)