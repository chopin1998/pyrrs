#!/usr/bin/python
#Filename:test.py

import os
import md5
import sys
import pty
import time
import math
import select
import base64
import signal
from optparse import OptionParser
from socket import *

from Crypto.Cipher import AES

class AES_SOCKET( object ):
    DFL_AES_KEY = 'powered_by_linux' * 2
    AES_PAD = chr(0x80)

    CIPHER_HEAD = chr(0x02)
    CIPHER_TAIL = chr(0x03)
    mmrrs_cmd_continue = chr(0xa1)

    BUFF_SIZE = 8192
    RECV_BUFF = ''
    SPLIT_SIZE = 1024

    def __init__(self, sock_desc, AES_KEY=DFL_AES_KEY):
        if len(AES_KEY) == 32:
            print '[II] using crypttext communication'
            self.crypt_obj = AES.new(AES_KEY, AES.MODE_ECB)
            self.EN_CRYPT = True
        else:
            print '[WW] using plaintext communication'
            self.EN_CRYPT = False

        self.sd = sock_desc

    def fileno(self):
        return self.sd.fileno()

    def recv(self, bufsize=BUFF_SIZE):
        if self.EN_CRYPT:
            try:
                new_data = self.sd.recv(bufsize)
                if new_data == '':
                    print '[DD] connection broken'
                    return False

                if len(self.RECV_BUFF) == 0:
                    self.RECV_BUFF = new_data
                else:
                    #print '[DD] last buff not empty'
                    self.RECV_BUFF += new_data
            except Exception, ex:
                print '[EE] recv error', ex
                return False

            packets = self.RECV_BUFF.split(self.CIPHER_TAIL+self.CIPHER_HEAD)
            if len(packets) == 1:
                if packets[0][-1] == self.CIPHER_TAIL:
                    packets[0] = packets[0][:-1]
                    self.RECV_BUFF = ''
                else:
                    return chr(0x90) + self.mmrrs_cmd_continue
            else: # more packets
                if packets[0][0] != self.CIPHER_HEAD:
                    self.RECV_BUFF = ''
                    print '[EE] BAD PACKET: WITHOUT CIPHER_HEAD'
                    return False
                else:
                    packets[0] = packets[0][1:] # remove first CIPHER_HEAD

                if packets[-1][-1] != self.CIPHER_TAIL:
                    unfinished = packets.pop()
                    unfinished = self.CIPHER_HEAD + unfinished
                    self.RECV_BUFF = unfinished
                else:
                    packets[-1] = packets[-1][:-1] # remove last CIPHER_TAIL
                    self.RECV_BUFF = ''

            all = ''
            for packet in packets:
                plain_data = base64.b64decode(packet)
                if len(plain_data) % AES.block_size != 0:
                    print '[DD] got a cipher data that length is not correct'
                    return False
                try:
                    tmp = self.crypt_obj.decrypt(plain_data)
                    tmp = tmp[:tmp.find(self.AES_PAD)]
                    all += tmp
                except Exception,ex:
                    print '[EE] DECRYPT ERROR!', ex
                    return False
            return all

        else: # for plaintext
            try:
                return self.sd.recv(bufsize)
            except:
                return False

    def _send_split(self, plain_data):
        tmp_buff = list()

        for i in range( int( math.ceil( len(plain_data) / float(self.SPLIT_SIZE) ) ) ):
            tmp_data = plain_data[i*self.SPLIT_SIZE : (i+1)*self.SPLIT_SIZE]

            pads = self.AES_PAD * (AES.block_size - len(tmp_data) % AES.block_size)
            if len(pads) == 0:
                pads = self.PAD * AES.block_size
            tmp_data += pads
            cipher_data = self.crypt_obj.encrypt(tmp_data)
            cipher_data = base64.b64encode(cipher_data)
            cipher_data = self.CIPHER_HEAD + cipher_data + self.CIPHER_TAIL

            tmp_buff.append(cipher_data)
        return tmp_buff

    def send(self, plain_data):
        if self.EN_CRYPT:
            splited = self._send_split(plain_data)
            for unit in splited:
                try:
                    self.sd.sendall(unit)
                except Exception, ex:
                    print '[DD] sending False:', ex
                    return False

        else: # for plaintext
            try:
                self.sd.sendall(plain_data)
            except:
                return False

