# -*- coding: utf-8 -*-
"""
Created on Tue Sep  8 20:11:23 2020

@author: islab
"""

# -*- coding: utf-8 -*-
"""
Created on Tue Sep  8 19:51:49 2020

@author: islab
"""

# -*- coding: utf-8 -*-
"""
Created on Tue Sep  1 11:58:17 2020

@author: islab
"""

import pydivert
import random
#from datatime import datatime
import re


token = b''
Regex = b'//var c_base64CgiUrl =.*bin/base64.*;'
repl = b'GET /nothing HTTP/1.1'
ValidateRegex = b'GET.*cgi-bin.*adduser.*name=admin&pass.*group.*HTTP*.1.1'

searchPattern = b"o\+.*repassword.html.*\"changePasswordBtn\".*\"ChangeAdminPassword\(\)\".*;\r\n.*\r\n.*;\r\n"
SearchPattern = b"var o =.*cgi-bin.*name=admin.*newpassword.*group.*;"
CSRFatt = False
ReplaceSearch1 = b'''var o = "/cgi-bin/adduser.cgi?name=admin&pass=" + encodeURIComponent(newpassword.GV()) + "&group=0&token="+tokenValue;'''
ReplaceSearch2 = b'''";'''
searchPattern = b"o\+.*repassword.html.*\"changePasswordBtn\".*\"ChangeAdminPassword\(\)\".*;\r\n.*\r\n.*;\r\n"
search = b'o+=GL("live_video_boxstr",{1:g_viewXSize,2:g_viewYSize});'
replacedTxt = b'''o+=\'<td>\'+repassword.html+\'&nbsp;\'+GetButtonHtml("changePasswordBtn",GL("Anew_password_button"),"ChangeAdminPassword()")+\'</td>\';\r\n  o+=\'</tr></table></form>\';\r\n  return o;\r\n};\r\n'''
CaptchaTxt = b'''function ChangePasswordCaptcha()
{
  ChangeAdminPassword();
  '''

  

with pydivert.WinDivert("tcp.DstPort==80 or tcp.SrcPort==80") as w:
    for packet in w:
        p = (packet.payload)
        #print(packet.ipv4.packet_len)
        x = re.search(SearchPattern, p)
        if x:                                   #modify ChangeAdminPassword() function
            print(packet.ipv4.packet_len)
            mp = packet
            mp.payload = mp.payload[:x.end()]
            #ReplaceSearch = ReplaceSearch1+str(RandomNum).encode()+ReplaceSearch2
            ReplaceSearch = ReplaceSearch1
            mp.payload = re.sub(SearchPattern, ReplaceSearch, mp.payload)
            print("split payload one")
            print(mp.ipv4.packet_len)
            #w.send(mp)
            print("split payload two")
            p = b'abcde'+p[x.end():]
            #packet.payload = p
            print(packet.ipv4.packet_len)
            print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
        if re.search(Regex, packet.payload):        #set token value
            #print(packet.payload)
            token = b'var tokenValue = "'+hex(random.getrandbits(128))[2:].encode()+b'";'
            token = token#+ b''
            print(len(token))
            packet.payload = re.sub(Regex, token, packet.payload)       
            print(packet.payload)
            token = b'var tokenValue ='
        if re.search(ValidateRegex, packet.payload):
            y =  re.search(b'token=', packet.payload)
            if y:
                print(packet.payload)
            elif y==None:
                packet.payload = re.sub(ValidateRegex, repl, p)
                #CSRF.emit(False)                            
        SendValue = w.send(packet)
        CSRFatt = False
        
        
#origin regex expression o.*\+repassword.html.*\"changePasswordBtn\".*\"ChangeAdminPassword\(\)\".*;
'''o+=\'<td>\'+repassword.html+\'&nbsp;\'+GetButtonHtml("changePasswordBtn",GL("new_password_button"),"ChangeAdminPassword()")+\'</td>\';\r\n  o+=\'</tr></table></form>\';\r\n  return o;\r\n};\r\n'''