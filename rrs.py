#!/usr/bin/python

try:
    import psyco
    psyco.full()
except:
    print '[SS] install "psyco" to get speed a little(but really) fast'
    pass

import os
import sys
import md5
import time
import signal
import fcntl
import struct
from optparse import OptionParser

import pty
import tty
import getpass

import select
from socket import *
from aes_socket import AES_SOCKET

from Crypto.Hash import SHA256
from Crypto.Cipher import AES

##############################
# global var(s) for protocol #
##############################
""" mmrrs protocol
mmrrs_special_command(1byte) | command(1byte) | parameter(0 or n-bytes)
"""

global mmrrs_special_command
global mmrrs_cmd_change_wsize
mmrrs_special_command = chr(0x90)
mmrrs_cmd_change_wsize = chr(0xa0) # followed with 2 integers stands for terminal row & col

##############################
# global var(s) for listener #
##############################
global g_listener_old_ttyattr
global g_listener_win_changed

###############################
# global var(s) for connector #
###############################

def listener_auth(asd):
    print 'You wanna login, so..'
    passwd = getpass.getpass()
    asd.send(passwd)

def listener_sig_handler(signum, frame):
    """ listener signal handler
    """
    global g_listener_old_ttyattr
    global g_listener_win_changed

    if signum in [signal.SIGINT, signal.SIGTERM]:
        print '[II] listener terminated forcefully, restore terminal attributes'
        tty.tcsetattr(sys.stdin, tty.TCSAFLUSH, g_listener_old_ttyattr)
        os.abort()
    elif signum is signal.SIGWINCH:
        g_listener_win_changed = True

def listener(port):
    print '\tworking in *** listener *** mode\n'

    """ declare global var(s) """
    global mmrrs_special_command
    global mmrrs_cmd_change_wsize
    global g_listener_old_ttyattr
    global g_listener_win_changed
    g_listener_old_ttyattr = tty.tcgetattr(sys.stdin)
    g_listener_win_changed = False
    """.end declare global var(s)"""

    sd = socket(AF_INET, SOCK_STREAM)
    sd.setsockopt(SOL_SOCKET, SO_REUSEADDR, True)
    sd.setsockopt(SOL_SOCKET, SO_KEEPALIVE, True)
    sd.setsockopt(SOL_TCP, TCP_KEEPCNT, 3)
    sd.setsockopt(SOL_TCP, TCP_KEEPINTVL, 2)
    sd.setsockopt(SOL_TCP, TCP_KEEPIDLE, 9)
    sd.bind(('0', port))
    sd.listen(1)
    cli_sd, cli_addr = sd.accept()
    print '[^_^] got connection from', cli_addr

    asd = AES_SOCKET(cli_sd)
    listener_auth(asd)

    """ setup signal handler """
    custom_signal_set = [signal.SIGINT, signal.SIGTERM, signal.SIGWINCH]
    for sig in custom_signal_set:
        signal.signal(sig, listener_sig_handler)
    """ .end setup signal handler """

    """ init tty winsize """
    print '[II] send local termios attributes..'
    winsize = struct.pack('hhhh', 0, 0, 0, 0) # for struct winsize in include/asm/termios.h
    struct_winsize = fcntl.ioctl(sys.stdin, tty.TIOCGWINSZ, winsize)
    data = mmrrs_special_command + mmrrs_cmd_change_wsize + struct_winsize
    asd.send(data)
    """ .end init tty winsize"""

    #tty.setcbreak(sys.stdin, tty.TCSANOW)
    tty.setraw(sys.stdin, tty.TCSAFLUSH)

    while True:

        try:
            stdin, stdout, stderr = select.select((asd, sys.stdin), (), ())
        except:
            pass
            #print '[DD] SELECT ERROR'
            #return False

        if g_listener_win_changed:
            struct_winsize = fcntl.ioctl(sys.stdin, tty.TIOCGWINSZ, winsize) # should be 2bytes * 4
            data = mmrrs_special_command + mmrrs_cmd_change_wsize + struct_winsize
            asd.send(data)
            g_listener_win_changed = False
            continue

        if asd in stdin:
            data = asd.recv()
            if not data:
                return False
            else:
                try:
                    os.write(sys.stdout.fileno(), data)
                except:
                    continue

        if sys.stdin in stdin:
            data = os.read(sys.stdin.fileno(), 1)
            if not data:
                return False
            else:
                asd.send(data)

def connector_sig_handler(signum, frame):
    if signum in [signal.SIGINT, signal.SIGTERM]:
        print '[II] connector terminated forcefully'
        os.abort()

def connector_auth(asd):
    if os.path.isfile('passwd'):
        try:
            data = asd.recv()
            #print '[DD] got passwd', repr(data)
        except:
            return False
        if data == '' or data is False:
            return False
        else:
            if open('passwd').read().strip() == SHA256.new(data).hexdigest():
                return True
            else:
                return False
    else:
        print '[WW] no password file given!'
        try:
            data = asd.recv()
        except:
            return False
        return True

def connector(hostenv):
    print '\tworking in *** connector *** mode\n'

    """ declare global var(s) """
    global mmrrs_special_command
    global mmrrs_cmd_change_wsize
    """.end declare global var(s)"""

    custom_signal_set = [signal.SIGINT, signal.SIGTERM]
    for sig in custom_signal_set:
        signal.signal(sig, connector_sig_handler)

    addr, port = hostenv
    sd = socket(AF_INET, SOCK_STREAM)
    sd.setsockopt(SOL_SOCKET, SO_KEEPALIVE, True)
    sd.setsockopt(SOL_TCP, TCP_KEEPCNT, 3)
    sd.setsockopt(SOL_TCP, TCP_KEEPINTVL, 2)
    sd.setsockopt(SOL_TCP, TCP_KEEPIDLE, 9)
    try:
        sd.connect((addr, port))
        print '[^_^] got connection from', sd.getpeername()
    except:
        print '[EE] cannot connect to', hostenv
        print '[SS] listener running or network robust?'
        return False
    asd = AES_SOCKET(sd)

    if connector_auth(asd):
        pass
    else:
        print '[EE] auth failed'
        return False

    master, slave = pty.openpty()
    pid = os.fork()
    if pid == 0: # child
        sd.close()
        os.close(master)
        os.setsid()
        os.dup2(slave, 0)
        os.dup2(slave, 1)
        os.dup2(slave, 2)
        os.close(slave)
        os.execl('/bin/sh')

    else: # parent
        os.close(slave)
        while True:
            try:
                stdin, stdout, stderr = select.select((asd, master), (), ())
            except:
                print '[DD] SELECT ERROR'
                #return False

            if asd in stdin:
                try:
                    data = asd.recv()
                except:
                    return False
                if not data:
                    return False
                else:
                    if data[0] == mmrrs_special_command:
                        if data[1] == mmrrs_cmd_change_wsize:
                            try:
                                row, col = struct.unpack('hhhh', data[2:])[0:2]
                                print '[DD] set terminal wsize to %d x %d' %(row, col)
                                fcntl.ioctl(master, tty.TIOCSWINSZ, data[2:])
                            except:
                                print '[DD] it should not be happend, but terminal size error'
                        elif data[1] == AES_SOCKET.mmrrs_cmd_continue:
                            continue
                        else:
                            print '[DD] command not implement yet'
                    else: # normal data
                        try:
                            os.write(master, data)
                        except:
                            return False

            if master in stdin:
                try:
                    data = os.read(master, 8192)
                except:
                    return False
                if not data:
                    return False
                else:
                    try:
                        asd.send(data)
                    except:
                        return False

def usage_ball(full=False):
    print 'usage:\t%s [ -c <addr:port> || -l <port> ]' %sys.argv[0]

    if full:
        print '\t%s is 2-in-1 program, you should choose one (and only) mode\n' %sys.argv[0]
        print '\t  mode -c (connector), should be called inside firewall'
        print '\t  mode -l (listener), should be called in a public host'
        print '\nauthor: marco@waven.com \t version: 0.1-03-2007-rc \t license: GPLv2'

#########################
#
#########################
if __name__ == '__main__':
    global g_listener_old_ttyattr
    if len(sys.argv) != 3:
        usage_ball(full=True)
    elif sys.argv[1] == '-c': ############### connector ###############
        hostenv = sys.argv[2].split(':')
        if len(hostenv) != 2:
            print '[EE] give addr and port in the format like: tree.waven.com:52911'
            sys.exit(-1)
        else:
            try:
                hostenv[1] = int(hostenv[1])
            except:
                print '[EE] port should be a number in range 1 ~ 65535'
                sys.exit(-1)
        while True:
            try:
                connector(hostenv)
            except Exception, ex:
                print '[WW] connector UNKNOW ERROR:', ex

            print '[II] connector finished, waitting for next'
            print '='*25 + '\n'
            time.sleep(3)

    elif sys.argv[1] == '-l': ############### listener ###############
        try:
            port = int(sys.argv[2])
        except:
            print '[EE] port should be a number in range 1 ~ 65535'
            sys.exit(-1)
        else:
            try:
                listener(port)
            except Exception, ex:
                print '[WW]listener UNKNOW ERROR:', ex

            tty.tcsetattr(sys.stdin, tty.TCSAFLUSH, g_listener_old_ttyattr)
            print '[BYEBYE] listener quit, real world back'

    else:
        usage_ball()
