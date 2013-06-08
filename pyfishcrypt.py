#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# FiSH/Mircryption clone for X-Chat in 100% Python
#
# Copyright 2012 trubo/segfault for irc.prooops.eu #py-fishcrypt trubo00+fish@gmail.com
# Released under the GPL
#
# Changelog:
#   * 5.0:
#      + start from scratch
#
###

import sys,os,binascii,hashlib,struct,re,uuid,time,errno,copy
from math import log

## Internationalization
#try:
#    import gettext
#except ImportError:
_ = lambda x:x

try:
    import simplejson as json
except ImportError:
    import json

SCRIPT_NAME = "fishcrypt"
SCRIPT_AUTHOR = "trubo <trubo00-fish@gmail.com> / segfault"
SCRIPT_VERSION = "5.0"
SCRIPT_LICENSE = "GPL3"
SCRIPT_DESC = _('fish encryption in pure python')


ISBETA = "beta20120924-1532"

UPDATEURL = 'http://pastebin.com/raw.php?i=ZWGAhvix'
BETAUPDATEURL = 'http://pastebin.com/raw.php?i=MFUhcYA2'
PYBLOWFISHURL = "http://pastebin.com/raw.php?i=nkExr9zu"
SOCKSIPYURL = 'http://socksipy-branch.googlecode.com/svn/trunk/socks.py'

ONMODES = ["Y","y","j","J","1","yes","on","ON","Yes","True","true"]
YESNO = lambda x: (x==0 and "N") or "Y"

DEBUGCHANNEL='>>debug<<'
#DEBUGCHANNEL=''

## check for valid irc target
VALID_IRC_TARGET_RE = re.compile("^[a-z_\-\[\]\\^{}|`#][a-z0-9_\-\[\]\\^{}|`]")
## only get the real nick not any prefix
VALID_IRC_NICK_RE   = re.compile("[a-z_\-\[\]\\^{}|`][a-z0-9_\-\[\]\\^{}|`]$")
IRC_PRIVMSG_RE      = re.compile("(:(?P<from>(?P<from_nick>.+?)!(?P<from_user>.+?)@(?P<from_host>.+?))\ )?PRIVMSG\ (?P<to>.+?)\ :(?P<text>.+)")

## check for Windows
IS_WINDOWS = sys.platform.startswith("win")

def prnt(msg,tochannel=''):
    print msg

def debug(msg,*args, **kwargs):
    dbgmsg = "DEBUG: %s" % (msg,)
    if args:
        dbgmsg = "%s [%r]" % (dbgmsg,args)
    if kwargs:
        dbgmsg = "%s [%r]" % (dbgmsg,kwargs)
    prnt (dbgmsg,tochannel=DEBUGCHANNEL)

try:
    import Crypto.Cipher.Blowfish as cBlowfish
except ImportError:
    try:
        import pyBlowfish as cBlowfish
        pyBlowfishlocation = "%s.py" % str(cBlowfish)[str(cBlowfish).find("from '")+6:str(cBlowfish).find(".py")]
        chksum = hashlib.sha1(open(pyBlowfishlocation,'rb').read()).hexdigest()
        if chksum in ['877ae9de309685c975a6d120760c1ff9b4c55719','57117e7c9c7649bf490589b7ae06a140e82664c6']:
            prnt (_("\0034** Loaded pyBlowfish.py with checksum: %s is untrusted") % chksum)
        else:
            prnt (_("\0033** Loaded pyBlowfish.py with checksum: %s") % chksum)

    except ImportError:
        prnt (_("\002\0034No Blowfish implementation"))
        if not IS_WINDOWS:
            prnt (_("This module requires PyCrypto / The Python Cryptographic Toolkit."))
            prnt (_("Get it from http://www.dlitz.net/software/pycrypto/. or"))
        else:
            path = path.replace(os.sep,os.sep*2)
        prnt (_("Download Python only Blowfish at %s") % PYBLOWFISHURL)
        prnt (_("or type \002/FISHSETUP\002 for automatic install of that"))

try:
    from Crypto.Util.strxor import strxor as xorstring
except ImportError:
    ## use slower python only xor
    debug ("python_only xorstring is used")
    def xorstring(a, b): # Slow.
        """xor string a and b, both of length blocksize."""
        xored = []
        for i in xrange(8):
            xored.append( chr(ord(a[i]) ^ ord(b[i])) )
        return "".join(xored)

def script_info():
    import inspect
    _script = inspect.currentframe().f_code.co_filename
    try:
        _script = os.readlink(_script)
    except (AttributeError,OSError):
        ## windows has no symlinks/ or _script is no symlink
        pass
    _path = os.sep.join(_script.split(os.sep)[:-1])
    ## append current path
    sys.path.insert(0,_path)

    return {
        'filename'  : "".join(_script.split(os.sep)[-1:]),
        'path'      : _path,
        'sha1'      : hashlib.sha1(open(_script,'rb').read()).hexdigest(),
    }

SCRIPT = script_info()

class shared_crypto_storage(object):
    def __init__(self):
        self.db_status = None
        self.db_file = os.path.join(SCRIPT['path'],'storage.crypto')
        self.db_key = None
        self.db_need_key = False
        self.db_cipher = 'CBC_BLOWFISH'
        self.db_iscrypted = False
        self.cipher_functions = {
            'CBC_BLOWFISH':BlowfishCBC,
        }
        self.db = {
            'networks': {},
            'configs': {},
        }
        self.load_db()
    def load_db(self):
        try:
            _hnd = open(self.db_file,'rb')
            _data = _hnd.read()
            self.db_time = os.path.getmtime(self.db_file)
            _hnd.close()
            _data = self.decrypt_data(_data)
            if _data:
                self.db = json.loads(_data)
                #keep a local copy of inital loaded db
                self._db = copy.deepcopy(self.db)
                ##TODO: send db hash to clients
                debug("DB:loaded %r" % self.db)
                self.db_defaults()
        except IOError,e:
            if e.errno not in [errno.ENOENT]:
                prnt(e)
            debug ("Create file %r" % self.db_file)
            self.save_db()

    def db_defaults(self):
        if not self.db.get('networks'):
            self.db['networks'] = {}
        if not self.db.get('configs'):
            self.db['configs'] = {}

    def save_db(self):
        debug("saving Database")
        _data = json.dumps(self.db)
        _data = self.encrypt_data(_data)
        try:
            _hnd = open(self.db_file,'wb')
            _hnd.write(_data)
            _hnd.close()
            ##TODO: send db hash to clients
        except IOError,e:
            if e.errno not in [errno.ENOENT]:
                prnt(e)

    def get_cipher_class(self,cipher=None):
        if not cipher:
            cipher = self.cipher
        
        _class = self.cipher_functions.get(cipher,lambda x: None)(self.db_key)
        if _class:
            self.cipher = cipher
        return _class

    def encrypt_data(self,data):
        if self.db_key:
            _cipher = get_cipher_class()
            if _cipher:
                data = "%s*** %s" % (self.cipher,_cipher.encrypt(data))
        return data

    def decrypt_data(self,data):
        _pos = data[:20].find("***")
        if _pos > 1:
            cipher = data[:_pos]
            if not self.db_key:
                debug("DB is crypted(%s) and no no key set" % cipher)
                self.db_need_key = True
                return None
            _cipher = get_cipher_class(cipher)
            if not _cipher:
                prnt("Cipher %r not supported DB not loaded")
                return None
            self.db_iscrypted = True
            data = _cipher.decrypt(data[_pos:])
            debug("decrypt_data: Encrypted Storage found with Cipher %r" % cipher)
        return data
        
        
    def get_network_db(self,network):
        g_netdb = self.db.get('networks')
        netdb = g_netdb.get(network)
        if not netdb:
            netdb = self.make_network_config(network)
            g_netdb[network] = netdb
        else:
            use_other_db = netdb.get("useotherdb")
            if use_other_db:
                other_db = self.get_network_db(use_other_db)
                if other_db:
                    debug ("get_network_db: using other db: %r" % other_db['network'])
                    netdb = other_db
        debug("get_network_db:",netdb)
        return netdb.get('db')

    def make_network_config(self,network):
        return {"network":network,"useotherdb": None, 'db' : {} }

    def get_config(self,script,default_config = {}):
        _loaded_config = self.db['configs'].get(script,{})

        #only load valid configs
        for key,value in default_config.iteritems():
            default_config[key] = _loaded_config.get(key,value)
        self.db['configs'][script] = default_config
        return default_config

    ## search dict key on keyword with method (startswith or endswith)
    def _search_dict(self,keyword,s_dict,method):
        _ret = {}
        for _key,_val in s_dict.iteritems():
            if method(_key,keyword):
                _ret[_key] = _val
        return _ret

    ## search dict for search pattern
    def search_dict(self,s_pattern,s_dict):
        debug("search_dict: %r %r" % (s_pattern,s_dict))
        if s_pattern.find("*") == -1:
            ## no wildcard so match direct
            return s_dict.get(s_pattern) and [s_pattern] or []

        _method = str.startswith
        _ret = s_dict
        for keyword in s_pattern.split("*"):
            if keyword:
                _ret = self._search_dict(keyword,_ret,_method)
            if _method == str.endswith:
                break
            _method = str.endswith
        debug("search_dict: pattern: %r returns %r" % (s_pattern,_ret.keys()))
        return _ret.keys()

class KeySizeError(Exception):
    pass

class CryptEnforceError(Exception):
    pass

class CryptoError(Exception):
    pass

class UserNotFoundError(Exception):
    pass

class client_message(object):
    def __init__(self,message,to_network=None,prefix=''):
        self.message = message
        self.to_network = to_network
        self.prefix = prefix
        self.error = None
    def __str__(self):
        return self.message
    def __repr__(self):
        return "<message: %r to_network; %r prefix: %r error: %r>" % (self.message,self.to_network,self.prefix,self.error)

class key_manager(object):
    def __init__(self):
        self.storage = shared_crypto_storage()

        debug("Create key_manager")
        self.config = self.storage.get_config('fishcrypt', {
            'plaintextmarker' : '+p',
            'MAXMESSAGELENGTH' : 300,
            'FISHDEVELOPDEBUG': False,
            'stealth_mode': False,
            'default_protected' : 0,
            'default_cipher' : 'CBC_BLOWFISH',
            'default_req-cipher': 0,
            }
        )
        ## TODO: defaults und einstellungene je netzwerk

        self.dh_manager = dh1080_manager()

        ## msg_prefix prefix: (function,NAME,priority)
        self.ciphers = {
            "CBC_BLOWFISH"  : (self.blowfish_cbc_encrypt,self.blowfish_cbc_decrypt, 5),
            "ECB_BLOWFISH"  : (self.blowfish_ecb_encrypt,self.blowfish_ecb_decrypt, 2),
            "DH1080INIT"    : (None,self.dh1080_init,-1),
            "DH1080FINISH"  : (None,self.dh1080_finish,-1),
        }
        self.msg_prefix = {
            "+OK *"           :"CBC_BLOWFISH",
            "mcps *"          :"CBC_BLOWFISH",
            "+OK "            :"ECB_BLOWFISH",
            "mcps "           :"ECB_BLOWFISH",
            "DH1080_INIT "    :"DH1080INIT",
            "DH1080_FINISH "  :"DH1080FINISH",
        }

    def __del__(self):
        prnt("Destroying Keymanager")

    def get_user(self,target,network,create=False,**kwargs):
        _db = self.storage.get_network_db(network)
        _user = _db.get(target)
        if not _user and create:
            debug("get_user: Creating user %s (%s)" % (target,network))
            _user = self.add_user(target,network,**kwargs)
        return _user


    def show_user(self,target,network):
        message_format = _("| %-20s | %-50s | %-3s | %-3s | %-15s |")
        _user = None
        _printed_lines = 0
        _printed_network = []
        _found_networks = self.storage.search_dict(network,self.storage.db.get('networks'))
        TIMETOTEXT = lambda x: time.strftime(_("%d.%m.%Y %H:%M"),time.localtime(x))
        for _network in _found_networks:
            _netdb = self.storage.get_network_db(_network)
            _found_users = self.storage.search_dict(target, _netdb)
            if len(_found_networks) == 1 and len(_found_users) == 1:
                ### details for single user
                _username = _found_users[0]
                _user = _netdb.get(_username)

                prnt(_("User: %-20s on %-25s added: %s") % (_username,_network,TIMETOTEXT(_user.get('date-add') )))
                _key = _user.get('key')
                if _key:
                    prnt(_("Key: %-50s set on %-20s") % (_key,TIMETOTEXT(_user.get('date-key'))))
                    prnt(_("Encryption activated: %s  Protected: %s  Cipher: %s") % 
                        (
                        YESNO(_user.get('encryption')),
                        YESNO( self.get_user_setting(_user,'protected')),
                        self.get_user_setting(_user,'cipher')
                        )
                    )
                return 
            for _username in _found_users:
                if _printed_lines % 20 == 0:
                    prnt(("\002%s\002" % message_format) % ("Username","Key","ENC","PRO","Cipher"))
                _printed_lines +=1

                if _network not in _printed_network:
                    prnt("-------- [ %s ] %s" % (_network,"-"*(80-len(_network))))
                    _printed_network.append(_network)

                _user = _netdb.get(_username)
                prnt( message_format  % 
                    (
                    _user.get('user'),
                    _user.get('key'),
                    YESNO(_user.get('encryption')),
                    YESNO( self.get_user_setting(_user,'protected')),
                    self.get_user_setting(_user,'cipher')
                    )
                )
        if not _user:
            prnt(_("User %s (%s) not found in DB") % (target,network))
            return 

    def add_user(self,target,network,cipher=-1,priority=-1,pubkey=None,protected=-1,encryption=-1,**kwargs):
        _db = self.storage.get_network_db(network)
        now = int(time.time())
        ## FIXME: wofür noch priority?
        if priority < 0:
            ## keyexchange cipher 
            #cipher = self.config['default_cipher']
            #protected = self.config['default_protected']
            encryption = 1

        _db[target] = {
            "uuid"      : uuid.uuid4().hex,
            "user"      : target,
            "key"       : None,
            "cipher"    : cipher,
            "sessionkey": None,
            "date-add"  : now,
            "date-seen" : now,
            "seen-as"   : target,
            "pub-key"   : pubkey,
            "encryption": encryption,
        }
#            "protected" : protected,
#            "req-cipher": -1,
        self.storage.save_db()
        debug("add_user: %r",_db)
        return _db[target]

    def del_user(self,target,network):
        pass

    def get_user_setting(self,_user,setting_name):
        val = _user.get(setting_name,-1)
        if val == -1:
            val = self.config.get("default_%s" % setting_name,-1)
            if val == -1:
                raise ValueError("setting %r has no default" % setting_name)
        return val

    def set_user_setting(self,_user,create=False,save=True,**kwargs):
        if not _user:
            raise UserNotFoundError
        for keyword,value in kwargs.iteritems():
            if keyword == "key":
                _user['date-key'] = int(time.time())
            _user[keyword] = value
        if save:
            self.storage.save_db()
        return True

    def set_key(self,key,target,network):
        if len(key) < 8 or len(key) > 56:
            raise KeySizeError(_("Key must be between 8 and 56 chars"))
        _user = self.get_user(target,network,create=True)
        self.set_user_setting(_user,key=key,encryption=1)
        debug("set_key:",**_user)

    def decrypt(self,message,target,network):
        debug("key_manager.decrypt: %r" % dict(message=message,target=target,network=network))
        ret = None
        for prefix in self.msg_prefix.keys():
            if message.startswith(prefix):
                cipher = self.msg_prefix[prefix]
                encrypt_func,decrypt_func,priority = self.ciphers.get(cipher)
                _user = self.get_user(target,network,priority=priority,cipher=cipher,create=True)

                try:
                    ret = decrypt_func(_user,message[len(prefix):],target,network)
                    debug("key_manager.decrypt: %r" % dict(cipher=cipher,priority=priority,ret=ret))
                except CryptoError,e:
                    prnt(e)
                    return client_message("\003%s" % message,prefix="?")
                ##TODO catch all unknown exceptions and write traceback to debug channel
                break

        return ret

    def encrypt(self,message,target,network,enforce=False):
        debug ("key_manager.encrypt: %r" % dict(enforce=enforce,target=target,network=network,message=message))
        if message.startswith(self.config['plaintextmarker']):
            message = message[len(self.config['plaintextmarker']):].lstrip()
            return (client_message(message,to_network=message))

        _user = self.get_user(target,network)
        if not _user:
            return None

        if not _user.get('key'):
            if (enforce or self.get_user_setting(_user,"req-cipher") > 0):
                raise CryptEnforceError(_("Encryption enforced: message not sent"))
            return None

        if not _user.get("encryption") and not enforce:
            debug("why im leaving here")
            return None
        encrypt_func,decrypt_func,priority = self.ciphers.get(self.get_user_setting(_user,"cipher"))
        try:
            return_message = encrypt_func(_user, message,target,network)
        except CryptoError,e:
            prnt(e)
        ##TODO catch all unknown exceptions and write traceback to debug channel
        debug("encrypt:%r" % return_message)
        return return_message

    ## mirccryption container
    def mirc_cryption_pack(self,data,prefix):
        return "%s%s" % (prefix,data.encode("base64"))

    def mirc_cryption_unpack(self,data):
        data = self.fix_b64_padding(data)
        try:
            return data.decode("base64")
        except binascii.Error:
            return ""

    ## blowcrypt container
    def blowcrypt_pack(self,data,prefix):
        return "%s%s" % (prefix,blowcrypt_b64encode(data))

    def blowcrypt_unpack(self,data):
        data = self.fix_b64_padding(data)
        return blowcrypt_b64decode(data)

    ## try to fix base64 padding
    def fix_b64_padding(self,data):
        pad_err = len(data) % 4
        if pad_err:
            debug("fix_b64_padding %r (%r)" % (data,pad_err))
            if pad_err > 2:
                data = "%s%s" % (data,"=" *(4-pad_err))
            else:
                data = data[:-pad_err]
        return data

    def blowfish_cbc_encrypt(self,user,message,target,network):
        key = user.get('key')
        if not key:
            return None

        return client_message(message,to_network=self.mirc_cryption_pack(
                BlowfishCBC(key).encrypt(message),"+OK *"
            ),prefix="°°"
        )

    def blowfish_cbc_decrypt(self,user,message,target,network):
        key = user.get('key')
        if not key:
            return None

        return client_message(
            BlowfishCBC(key).decrypt(
                self.mirc_cryption_unpack(message)
            ),prefix="°°"
        )

    def blowfish_ecb_encrypt(self,user,message,target,network):
        key = user.get('key')
        if not key:
            return None

        return client_message(message,to_network=self.blowcrypt_pack(
                Blowfish(key).encrypt(message),"+OK "
            ),prefix="°"
        )

    def blowfish_ecb_decrypt(self,user,message,target,network):
        key = user.get('key')
        if not key:
            return None

        return client_message(
            Blowfish(key).decrypt(
                self.blowcrypt_unpack(message)
            ),prefix="°"
        )

    def dh1080_init(self,user,message,target,network):
        debug("dh1080_init: %s(%s) %r" % (target,network,message))

        ## dont add default values until we check for stealth mode
        #_user = self.get_user(target,network,priority=0,create=True)
        
        ## create keypair
        token = self.dh_manager.gen_keypair(user.get('uuid'))
        ## store the remote partys public key
        self.dh_manager.set_remote_pub_key(user.get('uuid'),self.dh_manager.unpack(message))
        to_network = None

        _additional_info = ""
        ## TODO: mirc CBC detection ... word[5]
        if not self.config.get("stealth_mode"):
            _send_status = ""
            #self.set_user_setting(_user,encrytion=1)
            _key = self.dh_manager.get_secret(user.get('uuid'))
            self.set_user_setting(user,key=_key,encryption=1)
            debug("dh1080_init: key set to %r" % user['key'])
            to_network = self.dh_manager.pack("DH1080_FINISH",token)
            debug("dh1080_init: send %r" % to_network)
            ## destroy the token object
            self.dh_manager.destroy(user.get('uuid'))
            if not self.get_user_setting(user,"protected"):
                to_network = _("User has key protection activated, exchange blocked - waiting for aproval")
                _send_status = "(PROTECTED) "

        else:
            _send_status = "(STEALTH) "
        if _send_status:
            _additional_info = _(" accept with /KEYX %s " % target)

        return client_message(_("%sDH1080 Keyexchange received from %s (%s)%s") % 
            (_send_status,target,network,_additional_info),
            to_network=to_network
        )
    def dh1080_finish(self,user,message,target,network):
        debug("dh1080_finish: %s(%s) %r" % (target,network,message))
        #_user = self.get_user(target,network)
        #if not user:
        #    return client_message(_("DH1080_FINISH received but not requested, ignoring"))
        token = self.dh_manager.db.get(user.get('uuid'))

        if not token:
            return client_message(_("DH1080_FINISH received but not requested, ignoring"))
        self.dh_manager.set_remote_pub_key(user.get('uuid'),self.dh_manager.unpack(message))
       
        _key = self.dh_manager.get_secret(user.get('uuid'))
        if not _key:
            _message = _("DH1080 exchange Token expired")
            return client_message(None,to_network=_message)
        self.set_user_setting(user,key=_key)
        debug("dh1080_finish: key set to %r" % user['key'])
        
        ## destroy the token object
        self.dh_manager.destroy(user.get('uuid'))
        
        return client_message(_("DH1080 Keyexchange with %s (%s) finished") % (target,network),to_network=None)

    def dh1080_start(self,user,target,network):
        debug("dh1080_start: %s(%s) %r" % (target,network,user))
        token = self.dh_manager.db.get(user.get('uuid'))
        ## check if there is allready a valid token
        if token:
            try:
                _key = self.dh_manager.get_secret(user.get('uuid'))
            except AssertionError:
                return client_message(_("DH1080 Keyexchange with %s still outstanding") % target)
            if _key:
                self.set_user_setting(user,key=_key,encryption=1)
                debug("dh1080_start: previously rejected key set to %r" % user['key'])
                to_network = self.dh_manager.pack("DH1080_FINISH",token)
                ## destroy the token object
                self.dh_manager.destroy(user.get('uuid'))
                return client_message(_("DH1080 Keyexchange with %s accepted") % target,to_network=to_network)

        token = self.dh_manager.gen_keypair(user.get('uuid'))
        to_network=self.dh_manager.pack("DH1080_INIT",token)
        return client_message(_("DH1080 Keyexchange with %s initiated") % target,to_network=to_network)

    def key_exchange(self,target,network):
        _user = self.get_user(target,network,priority=-1,create=True)
        return self.dh1080_start(_user,target,network)


class irc_client_interface(object):
    ## debugging
    def evaldebug(self,word, word_eol, userdata):
        eval(compile(word_eol[1],'develeval','exec'))
        return xchat.EAT_ALL
    ## return the nick from a full usermask
    def get_nick(self,full):
        full = full.lstrip(":")
        identpos = full.find('!')
        if identpos > -1:
            return full[:identpos]
        return full



### XCHAT/Hexchat ###
class xchat_client_interface(irc_client_interface):
    def __init__(self):
        prnt (_("\0032Fishcrypt Version %s\003") % ("%s %s" % (__module_version__,ISBETA)))
        prnt ("SHA1 checksum: %r" % SCRIPT['sha1'])
        self.interface_type = "xchat"

        self.__context_lock_map = {}
        
        self.key_manager = key_manager()

        self.helpmessages = {
            "MSG+"          : (1, "<channel|nick> <message>",    _("send crypted msg regardless of /ENCRYPT setting")),
            "ME+"           : (2, "<message>",                   _("send crypted CTCP ACTION")),
            "NOTICE+"       : (3, "<channel|nick> <message>",    _("send crypted notice regardless of /ENCRYPT setting")),
            "PRNDECRYPT"    : (4, "<cryptedmessage>",            _("decrypts messages localy")),
            "PRNCRYPT"      : (5, "<messages>",                  _("encrypts messages localy")),
            "KEYX"          : (6, "[<nick>]",                    _("make a Key exchange")),
            "SETKEY"        : (7, "[<channel|nick>] <key>",      _("set a new key for (current) nick or channel")),
            "KEY"           : (8, "[<channel|nick|*>]",          _("show keys matching context/nick/or wildcard")),
            "DELKEY"        : (9, "[<channel|nick>|*]",          _("delete the key for channel/nick/wildcard")),
            "CBCMODE"       : (10,"[<channel|nick>] <0/1>",      _("enable/disable CBC Mode for nick/channel")),
            "PROTECTKEY"    : (11,"[<channel|nick>] <0/1>",      _("enable/disable protection for nick/channel")),
            "ENCRYPT"       : (12,"[<channel|nick>] <0/1>",      _("enable/disable encryption for nick/channel")),
            "DBPASS"        : (13,"", _("set/change the passphrase for the Key Storage")),
            "DBLOAD"        : (14,"", _("loads the Key Storage")),
            "SET"           : (15,"", _("show/set fishcrypt settings")),
        }
        self.xchat_hooks = []
        ## Commands
        self.hook('HELP',                       self.cmd_help)

        self.hook('',                           self.cmd_msg)
        self.hook('MSG',                        self.cmd_msg)
        self.hook('MSG+',                       self.cmd_msg)
        self.hook('ME+',                        self.cmd_msg)
        self.hook('NOTICE',                     self.cmd_msg)
        self.hook('NOTICE+',                    self.cmd_msg)
        self.hook('PRNCRYPT',                   self.cmd_prncrypt,)
        self.hook('PRNDECRYPT',                 self.cmd_prndecrypt)

        self.hook('KEYX',                       self.cmd_keyx)
        self.hook('SETKEY',                     self.cmd_setkey)
        self.hook('KEY',                        self.cmd_key)
        self.hook('DELKEY',                     self.cmd_delkey)
        self.hook('CBCMODE',                    self.cmd_cbcmode)
        self.hook('PROTECTKEY',                 self.cmd_protectkey)
        self.hook('ENCRYPT',                    self.cmd_encrypt)
       
        self.hook('CRYPT',                      self.cmd_set)
        self.hook('DBPASS',                     self.cmd_dbpass)
        self.hook('DBLOAD',                     self.cmd_dbload)


        self.hook('FISHEVAL',                   self.evaldebug)

        ## Server Messages
        self.hook('332',                        self.server_topic,   hooktype='server', priority=xchat.PRI_HIGH)
        self.hook('topic',                      self.server_topic,   hooktype='server', priority=xchat.PRI_HIGH)
        self.hook('notice',                     self.server_notice,  hooktype='server', priority=xchat.PRI_HIGH, userdata='Notice')

        ## Xchat Messages
        self.hook('Notice Send',                self.print_notice,   hooktype='print', priority=xchat.PRI_HIGH)
        
        self.hook('Channel Action',             self.print_msg,      hooktype='print', priority=xchat.PRI_HIGH)
        self.hook('Private Action to Dialog',   self.print_msg,      hooktype='print', priority=xchat.PRI_HIGH)
        self.hook('Private Action ',            self.print_msg,      hooktype='print', priority=xchat.PRI_HIGH)
        self.hook('Channel Message',            self.print_msg,      hooktype='print', priority=xchat.PRI_HIGH)
        self.hook('Private Message to Dialog',  self.print_msg,      hooktype='print', priority=xchat.PRI_HIGH)
        self.hook('Private Message',            self.print_msg,      hooktype='print', priority=xchat.PRI_HIGH)

        self.hook('Process Already Running',    self.plugin_msg,     hooktype='print', priority=xchat.PRI_HIGHEST)

        self.hook('Key Press',                  self.print_keypress, hooktype='print')
        self.hook('Change Nick',                self.print_nick,     hooktype='print')
    ## add hooks
    def hook(self,what,func,hooktype='command',**kwarg):
        ## get hook function
        _hook = getattr(xchat,"hook_%s" % hooktype,None)

        if not _hook:
            return

        if not kwarg.get('userdata'):
            kwarg['userdata'] = what
        helpmsg = self.helpmessages.get(what)
        if helpmsg and what != "SET":
            kwarg['help'] = _("usage: %s %s %s") % (what,helpmsg[1],helpmsg[2])
        if not self.xchat_hooks:
            self.xchat_hooks.append(('unloadhook',xchat.hook_unload(self.unload_interface)))

        self.xchat_hooks.append(('%s_%s' % (hooktype,what),_hook(what,func,**kwarg)))

    ## unload Interface and unhook all functions
    def unload_interface(self,userdata):
        del self.key_manager 
        for desc,hook in self.xchat_hooks:
            #debug ("unhooking %r %r" % (desc,hook))
            xchat.unhook(hook)
        destroy_client_interface()

    ## destructor
    def __del__(self):
        xchat.prnt (_("\00311fishcrypt.py successful unloaded"))

    def usage(self,command):
        help = self.helpmessages.get(command,None)
        if not help:
            prnt( _("No help available for %r" % command))
        prnt (_("usage: %s %s %s") % (command,help[1],help[2]))

    ## show help
    def cmd_help(self,word, word_eol, userdata):
        if len(word) < 2:
            print _("\n\0033 For fishcrypt.py help type /HELP FISHCRYPT")
            return xchat.EAT_NONE
        if word[1].upper() == "FISHCRYPT":
            print ""
            print "\002\0032 ****  fishcrypt.py Version: %s %s ****" % (__module_version__,ISBETA)
            print "\0036 %s" % UPDATEURL
            print "\n"
            print _(" \002\00314***************** Fishcrypt Help ********************")
            print " -----------------------------------------------------"
            for command,helpitem in sorted(self.helpmessages.items(),key=lambda (k,v): (v,k)):
                print "/%-12s: \00314%-25s\003 %s" % (command,helpitem[1],helpitem[2])
            return xchat.EAT_ALL

    ## Inter Plugin communication
    def plugin_msg(self,word, word_eol, userdata):
        if word:
            print "PLUGIN MSG: %r" % word_eol[0]
            return xchat.EAT_XCHAT
        return xchat.EAT_NONE

    ## load the database
    def cmd_dbload(self,word, word_eol, userdata):
        
        return xchat.EAT_ALL

    ## set a password for the database
    def cmd_dbpass(self,word, word_eol, userdata):
        xchat.command('GETSTR "" "SET fishcrypt_passpre" "%s"' % _("New Password"))
        return xchat.EAT_ALL

    ## show either key for current chan/nick or all
    def cmd_key(self,word, word_eol, userdata):
        network = None
        if len(word) >1:
            target = word[1]
            if target.find("@") > 0:
                target,network = target.split("@",1)
        else:
            target = None

        if not network:
            target,network = self.get_id(target)

        self.key_manager.show_user(target,network)
        return xchat.EAT_ALL

    ## start the DH1080 Key Exchange
    def cmd_keyx(self,word, word_eol, userdata):
        if len(word) >1:
            target = word[1]
        else:
            target = None

        target,network = self.get_id(target)
        if not VALID_IRC_TARGET_RE.match(target):
            debug("cmd_msg: no valid irc target")
            return xchat.EAT_ALL

        ## FIXME chan notice - what should happen when keyx is send to channel trillian seems to accept it and send me a key --
        if target.startswith("#"):
            print _("Channel Exchange not implemented")
            return xchat.EAT_ALL

        msg_obj = self.key_manager.key_exchange(target,network)

        if msg_obj.message:
            self.emit_print("Notice",target,msg_obj.message,target=target)

        if not msg_obj.to_network:
            return xchat.EAT_ALL
        
        ## lock the target
        self.__set_proc_state(True,target=target)
        ## send key with notice to target
        debug("sending %r" %'QUOTE NOTICE %s %s' % (target, msg_obj.to_network))
        xchat.command('QUOTE NOTICE %s %s' % (target, msg_obj.to_network))
        ## release the lock
        self.__set_proc_state(False,target=target)


        return xchat.EAT_ALL

    def to_utf8(self,message):
        charset = xchat.get_info('charset')
        if charset == "IRC":
            charset = "utf-8"
        try:
            unicode_message = message.decode(charset)
            debug("to_utf8: %r (%r) (%r)" % (charset,unicode_message,message))
        except UnicodeError,e:
            debug("to_utf8: UnicodeError: %r" % (e,))
            unicode_message = unicode(message,charset,'replace')
        except LookupError,e:
            debug("to_utf8: LookupError: %r" % (e,))
            unicode_message = unicode(message,"utf-8",'replace')
        #return unicode_message.encode("utf-8")
        return message

    ## print encrypted localy
    def cmd_prncrypt(self,word, word_eol, userdata):
        if len(word_eol) < 2:
            self.usage(userdata)
            return xchat.EAT_ALL
        message = self.to_utf8(word_eol[1])
        target, network = self.get_id()
        msg_obj = self.key_manager.encrypt(message,target,network,enforce=True)
        if not msg_obj:
            ## No crypto information found
            prnt (_("\0034No Key found for %s") %  target)
            return xchat.EAT_ALL
        prnt ("\0032%s" % msg_obj.to_network)
        return xchat.EAT_ALL

    ## print decrypted localy
    def cmd_prndecrypt(self,word, word_eol, userdata):
        if len(word_eol) < 2:
            self.usage(userdata)
            return xchat.EAT_ALL
        message = word_eol[1]
        target, network = self.get_id()
        msg_obj = self.key_manager.decrypt(message,target,network)
        if not msg_obj:
            ## No crypto information found
            prnt (_("\0034No Key found for %s") %  target)
            return xchat.EAT_ALL
            
        prnt ("\0032%s" % msg_obj.message )
        return xchat.EAT_ALL

    ## manual set a key for a nick or channel
    def cmd_setkey(self,word, word_eol, userdata):
        if len(word) < 2:
            self.usage(userdata)
            return xchat.EAT_ALL
        target, network = self.get_id()
        key = word[1]
        if len(word) > 2:
            target = word[1]
            if target.find("@") > 0:
                target,network = target.split("@",1)
            key = word[2]
        try:
            self.key_manager.set_key(key,target,network)
        except KeySizeError,e:
            prnt(e)
        return xchat.EAT_ALL

    ## delete a key or all
    def cmd_delkey(self,word, word_eol, userdata):

        return xchat.EAT_ALL

    ## settings and password handler
    def cmd_set(self,word, word_eol, userdata):
        debug("cmd_set: (%r) %r" % (userdata,word_eol[0]))
        fishonly = False
        if len(word) == 2:
            if word[1].upper() == "FISHCRYPT":
                fishonly = True
        if len(word) < 2 or fishonly:
            ## not for us 
            #print "fishcrypt_pass%s%s%s: \003%r" % (COLOR['blue'],"."*16,COLOR['green'],self.status['DBPASSWD'])
            for key in self.config:
                keyname = "%s%s" % (key,"."*20)
                print "\00312%.29s: %s" % (keyname,str(self.config[key]))
            if fishonly:
                return xchat.EAT_ALL
            return xchat.EAT_NONE


        if word[1] == "fishcrypt_passpre":
            if len(word) == 2:
                self.status['CHKPW'] = ""
            else:
                self.status['CHKPW'] = word_eol[2]
            xchat.command('GETSTR ""  "SET fishcrypt_pass" "%s"' % _("Repeat the Password"))
            return xchat.EAT_ALL

        if word[1] == "fishcrypt_pass":
            if len(word) == 2:
                if self.status['CHKPW'] <> "" and self.status['CHKPW'] <> None:
                    print "Passwords don't match"
                    self.status['CHKPW'] = None
                    return xchat.EAT_ALL
                self.status['DBPASSWD'] = None
                print _("\0034Password removed and Key Storage decrypted")
                print _("\0034Warning Keys are plaintext")
            else:
                if self.status['CHKPW'] <> None and self.status['CHKPW'] <> word_eol[2]:
                    print "Passwords don't match"
                    self.status['CHKPW'] = None
                    return xchat.EAT_ALL
                if len(word_eol[2]) < 8 or len(word_eol[2]) > 56:
                    print _("Passwords must be between 8 and 56 chars")
                    self.status['CHKPW'] = None
                    return xchat.EAT_ALL
                self.status['DBPASSWD'] = word_eol[2]
                ## don't show the pw on console if set per GETSTR
                if self.status['CHKPW'] == None:
                    print _("\0034Password for Key Storage encryption set to %r") % self.status['DBPASSWD']
                else:
                    print _("\0034Key Storage encrypted")
            self.status['CHKPW'] = None
            ##self.saveDB()
            return xchat.EAT_ALL

        if word[1] == "fishcrypt_passload":
            if len(word) > 2:
                if len(word_eol[2]) < 8 or len(word_eol[2]) > 56:
                    print _("Password not between 8 and 56 chars")
                else:
                    self.status['DBPASSWD'] = word_eol[2]
                    ##self.loadDB()
            else:
                print _("Key Storage Not loaded")
                self.status['DBPASSWD'] = None
            return xchat.EAT_ALL

        key = word[1].upper()
        if key in self.config.keys():
            if len(word) <3:
                keyname = "%s%s" % (key,"."*20)
                print "\00312%.29s: %s" % (keyname,str(self.config[key]))
            else:
                try:
                    if type(self.config[key]) == bool:
                        self.config[key] = bool(word[2] in ONMODES)
                    else:
                        self.config[key] = type(self.config[key])(word_eol[2])
                    print "\0035Set %r to %r" % (key,word_eol[2])
                    ##self.saveDB()
                except ValueError:
                    print _("\0034Invalid Config Value %r for %s") % (word_eol[2],key)
            return xchat.EAT_ALL

        return xchat.EAT_NONE

    ## set cbc mode or show the status
    def cmd_cbcmode(self,word, word_eol, userdata):
        return xchat.EAT_ALL

    ## set key protection mode or show the status
    def cmd_protectkey(self,word, word_eol, userdata):
        return xchat.EAT_ALL

    ## activate/deaktivate encryption für chan/nick
    def cmd_encrypt(self,word, word_eol, userdata):
        return xchat.EAT_ALL

    ## outgoing messages will be proccesed here
    def cmd_msg(self,word, word_eol, userdata):
        debug ("cmd_msg: %r userdata: %r" % (word, userdata))
        enforce = False
        command = "PRIVMSG"
        message_format = "%s"
        target = None
        text_event = None
        target_context = None
        ## check if we are called with a command
        if userdata:
            if len(word) < (userdata.startswith("ME") and 2 or 3):
                ## not enough parameter to run this command
                self.usage(userdata)
                return xchat.EAT_XCHAT

            if userdata.startswith("ME"):
                message_format = "\001ACTION %s\001"
                text_event = "Channel Action"
                message = word_eol[1]
            else:
                target = word[1]
                message = word_eol[2]

            ## commands with a + enforce encryption even if encryption is disabled
            if userdata.find("+") != -1:
                enforce = True

            if userdata.startswith("NOTICE"):
                command = "NOTICE"
                text_event = "Notice"

        else:
            message = word_eol[0]

        target,network = self.get_id(target)

        ## if target is not a valid IRC nick or channel
        if not VALID_IRC_TARGET_RE.match(target):
            debug("cmd_msg: no valid irc target")
            return xchat.EAT_NONE
            
        ## check if allready processed
        if self.__check_proc_state(target):
            return xchat.EAT_NONE

        nick = xchat.get_context().get_info('nick')
        message = self.to_utf8(message)

        ## check if we have an open tab for the target
        target_tab = xchat.find_context(channel=target)
        if not text_event:
            if not target_tab and target_tab != xchat.get_context():
                ## show in same tab
                text_event = "Message Send"
                nick = target
            else:
                ## show in users query tab
                text_event = "Your Message"
                target_context = target_tab

        maxlen = self.key_manager.config['MAXMESSAGELENGTH']
        ## split large messages to multiple smaller
        while len(message) >0:
            ## check if the message needs to be encrypted
            msg_obj = self.key_manager.encrypt(message[:maxlen],target,network,enforce=enforce)

            if not msg_obj:
                ## No crypto information found
                debug ("cmd_msg: not crypto information found")
                return xchat.EAT_NONE
            #if not prefix:
            #    message = crypted_message
            ## show the unencrypted localy
            if command == "NOTICE":
                ## add the target nick or channel to the nick
                nick = "%s/%s" % (nick,target)
            
            ## FIXME unicode usw...
            ## add prefix with info about encryption to the nick and send it with the unencrypted message to local target
            self.emit_print(text_event,"%s%s" % (msg_obj.prefix,nick) ,msg_obj.message,target=target,target_context=target_tab)

            if msg_obj.to_network:
                ## send encrypted message to target
                self.__set_proc_state(True,target=target)
                debug ("cmd_msg: sending %r to the server" % 'QUOTE %s %s :%s' % (command,target, message_format % msg_obj.to_network))
                xchat.command('QUOTE %s %s :%s' % (command,target, message_format % msg_obj.to_network))
                self.__set_proc_state(False,target=target)
            message = message[maxlen:]
        return xchat.EAT_ALL

    ## incoming notice received
    def server_notice(self,word, word_eol, userdata):
        debug ("server_notice: %r userdata: %r" % (word, userdata))
        if len(word) < 3:
            return xchat.EAT_NONE
        target = word[2]

        ## extract the nick from the usermask
        speaker = self.get_nick(word[0])

        ## remove leading : 
        message = word_eol[3].lstrip(":")

        if target.startswith("#"):
            target,network = self.get_id()
            speaker = "%s/%s" % (speaker,target)
        else:
            target,network = self.get_id(target)

        ## check if allready processing
        if self.__check_proc_state(target):
            return xchat.EAT_NONE

        msg_obj = self.key_manager.decrypt(message,speaker,network)
        debug("server_notice:",message=message)
        ## if not encrypted leave it to xchat
        if not msg_obj:
            debug ("server_notice: not encrypted")
            return xchat.EAT_NONE

        if msg_obj.message:       
            ## show the unencrypted message prefixed with encryption info prefixed to the nick
            self.emit_print(userdata,"%s%s" % (msg_obj.prefix,speaker),msg_obj.message,target=target)


        if msg_obj.to_network:
            self.__set_proc_state(True,target=target)
            debug ("server_notice: sending %r to the server" % 'QUOTE NOTICE %s :%s' % (speaker,msg_obj.to_network))
            xchat.command('QUOTE NOTICE %s :%s' % (speaker,msg_obj.to_network))
            self.__set_proc_state(False,target=target)
        
        return xchat.EAT_XCHAT

    ## handle topic server message
    def server_topic(self,word, word_eol, userdata):
        debug ("server_topic %r userdata: %r" % (word,userdata))
        
        ## 322 message parameter are different
        if userdata == '332':
            server, cmd, nick, channel, topic = word[0], word[1], word[2], word[3], word_eol[4]
        else:
            server, cmd, channel, topic = word[0], word[1], word[2], word_eol[3]

        target,network = self.get_id(channel)

        ## check if allready processing
        if self.__check_proc_state(target):
            debug("server_topic: allready processing")
            return xchat.EAT_NONE

        ## remove the leading :
        topic = topic[1:]
        msg_obj = self.key_manager.decrypt(topic,target,network)

        ## if its not encrypted leave
        if not msg_obj:
            debug("server_topic: not encrypted")
            return xchat.EAT_NONE

        ## lock the target
        self.__set_proc_state(True,target=target)

        ## send the message to xchat
        if userdata == '332':
            xchat.command('RECV %s %s %s %s :%s%s' % (server, cmd, nick, channel, msg_obj.prefix,msg_obj.message.replace("\x00","")))
        else:
            xchat.command('RECV %s %s %s :%s%s' % (server, cmd, channel, msg_obj.prefix,msg_obj.message.replace("\x00","")))
        ## release the lock
        self.__set_proc_state(False,target=target)

        return xchat.EAT_ALL

    ## incoming messages
    def print_msg(self,word, word_eol, userdata):
        debug ("print_msg: %r userdata: %r" % (word, userdata))

        speaker = word[0]
        message = word_eol[1]

        if userdata.startswith("Private"):
            target = speaker
        else:
            target = None

        target,network = self.get_id(target)
        
        ## check if allready processing
        if self.__check_proc_state(target):
            debug("print_msg: allready processing")
            return xchat.EAT_NONE

        ## remove mode char from message
        if len(word_eol) >= 3:
            message = message[:-2]

        msg_obj = self.key_manager.decrypt(message,target,network)
        
        ## nothing encrypted found leave
        if not msg_obj:
            return xchat.EAT_NONE

        ## send the unencrypted message prefixed with encryption info to the target
        self.emit_print(userdata,"%s%s" % (msg_obj.prefix,speaker),msg_obj.message,target=target)

        return xchat.EAT_ALL
        

    ## handle notices
    def print_notice(self,word, word_eol, userdata):
        debug ("print_notice: %r userdata: %r" % (word, userdata))
        ## check if allready processing
        if self.__check_proc_state():
            ## is allready handled
            debug ("EAT IT")
            return xchat.EAT_ALL
        return xchat.EAT_NONE

    ## trace nick changes
    def print_nick(self,word, word_eol, userdata):
        print "DEBUG print_nick: %r userdata: %r" % (word, userdata)
        return xchat.EAT_NONE

    ## handle keypress
    def print_keypress(self,word, word_eol, userdata):
        if word[0] not in ["65289","65056"]:
            return xchat.EAT_NONE
        input = xchat.get_info('inputbox')
        if input.upper().startswith("/SET F"):
            newinput = "/SET FISHCRYPT "
        else:
            return xchat.EAT_NONE
        xchat.command("SETTEXT %s" % newinput)
        xchat.command("SETCURSOR %d" % len(newinput))
        return xchat.EAT_PLUGIN


    ## send message to local xchat and lock it
    def emit_print(self,userdata,speaker,message,target=None,target_context=None):
        debug ("emt_print:", userdata=userdata,speaker=speaker,target=target,target_context=target_context,message=message)
        ## if no target context 
        if not target_context:
            ## use the current one
            target_context = xchat.get_context()

        ## FIXME
        if userdata == None:
            ## if userdata is none its possible Notice
            print "NEEDED??"
            userdata = "Notice"

        if not target:
            ## if no special target for the lock is set, make it the speaker
            target = speaker

        ## lock the processing of that message
        self.__set_proc_state(True,target=target)

        ## FIXME
        ## check for Highlight
        for hl in [xchat.get_info('nick')] + xchat.get_prefs("irc_extra_hilight").split(","):
            if len(hl) >0 and message.find(hl) > -1:
                if userdata == "Channel Message":
                    userdata = "Channel Msg Hilight"
                xchat.command("GUI COLOR 3")

        ## send the message
        target_context.emit_print(userdata,speaker, message.replace('\0',''))
        ## release the lock
        self.__set_proc_state(False,target=target)

    ## set or release the lock on the processing to avoid loops
    def __set_proc_state(self,state,target=None):
        ctx = xchat.get_context()
        if not target:
            ## if no target set, the current channel is the target
            target = ctx.get_info('channel')
        ## the lock is NETWORK-TARGET
        id = "%s-%s" % (ctx.get_info('network'),target)
        debug ("__set_proc_state: %r %s" % (id,state))
        self.__context_lock_map[id] = state

    ## check if that message is allready processed to avoid loops
    def __check_proc_state(self,target=None):
        ctx = xchat.get_context()
        if not target:
            ## if no target set, the current channel is the target
            target = ctx.get_info('channel')
        id = "%s-%s" % (ctx.get_info('network'),target)
        state = self.__context_lock_map.get(id,False)
        debug ("__check_proc_state: %r %s" % (id,state))
        return state

    def get_chan_type(self,ctx):
        ret = filter(lambda chan,ctx=ctx: chan.context==ctx,xchat.get_list('channels'))
        if not ret:
            return -1
        return ret[0].type

    # get an id from channel name and networkname
    def get_id(self,target=None):
        ctx = xchat.get_context()
        if not target:
            target = str(ctx.get_info('channel'))
            if self.get_chan_type(ctx) < 2:
                target = "????"

        ##return the id
        network = ctx.get_info('network')
        if not network:
            network = ctx.get_info('server')
        if not network:
            network = 'unknown'
        network = network.replace("*","_")
        return (target, network.lower())

### Weechat ###
class weechat_client_interface(irc_client_interface):
    def __init__(self):
        self.interface_type = "weechat"
        weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION,SCRIPT_LICENSE, SCRIPT_DESC, "weechat_unload_helper", "")

        weechat.hook_modifier("irc_in_privmsg", "weechat_server_message_helper", "")
        weechat.hook_modifier("irc_in_notice",  "weechat_server_message_helper", "")
        weechat.hook_modifier("irc_in_topic",   "weechat_server_message_helper", "")
        weechat.hook_modifier("irc_in_332",     "weechat_server_message_helper", "")
        weechat.hook_print("","notify_message","",0,"weechat_prnt_message_helper","a1")
        #weechat.hook_print("","notify_private","",0,"weechat_prnt_message_helper","a2")
        #weechat.hook_print("","notify_highlight","",0,"weechat_prnt_message_helper","a1")

        weechat.hook_modifier('irc_out_privmsg', 'weechat_outmessage_helper', '')
        self.hook_cmd("NOTICE+")
        self.hook_cmd("MSG+")
        self.hook_cmd("ME+")

        #self.hook_cmd("KEYX")
        weechat.hook_command("KEYX",'DH1080 Key exchange','[NICK]','','%(nick)','weechat_command_helper',"KEYX")
        weechat.hook_command("SETKEY",'set Key for nick or channel','[NICK NETWORK]','','%(nick)','weechat_command_helper',"SETKEY")

        self.hook_cmd("CBCMODE")
        self.key_manager = key_manager()

    def hook_cmd(self,command):
        weechat.hook_command(command,'description','start [NICK NETWORK]','','start %(nick)','weechat_command_helper',command)

    def unload_interface(self):
        destroy_client_interface()
        return weechat.WEECHAT_RC_OK

    def server_message(self,data, modifier, modifier_data, string):
        debug ("in_message",data=data,modifier=modifier,modifier_data=modifier_data,string=string)
        #DEBUG: in_message [{'modifier_data': 'Prooops', 'modifier': 'irc_in_NOTICE',  'data': 'irc_in_notice',  'string': ':hrh23!trubo@go.to.sleep NOTICE trubo_ DH1080_INIT S8TvfqT8a/XKM/6qa5m+1sSoIatpMR63LHbrxAJe5dSUumNiUeIx4gLqHJEJ8hszhb0XBO+nVeA90mvqMAqm7UfdpuIK1K3uOgCJL/8GqTltSk4rBw7Nlno65DL1yuPuolW6hAuWbrQ6CQnG0LeaUZuO47QJNXaMyPneRRHiJcxcr+ta64vkA'}]
        #DEBUG: in_message [{'modifier_data': 'Prooops', 'modifier': 'irc_in_TOPIC',   'data': 'irc_in_topic',   'string': ':hrh23!trubo@go.to.sleep TOPIC #fishtest :+OKt7d8m.3k/hu01z/X//Zb1ap1'}]
        #DEBUG: in_message [{'modifier_data': 'Prooops', 'modifier': 'irc_in_332',     'data': 'irc_in_332',     'string': ':kardia.prooops.com 332 trubo_ #fishtest :+OKt7d8m.3k/hu01z/X//Zb1ap1'}]        
        #DEBUG: in_message [{'modifier_data': 'Prooops', 'modifier': 'irc_in_PRIVMSG', 'data': 'irc_in_privmsg', 'string': ':hrh23!trubo@go.to.sleep PRIVMSG #fishtest :+OK 4ViEr0.yJYd1'}]
        #IRC_PRIVMSG_RE      = re.compile("(:(?P<from>(?P<from_nick>.+?)!(?P<from_user>.+?)@(?P<from_host>.+?))\ )?PRIVMSG\ (?P<to>.+?)\ :(?P<text>.+)")
        word = string.split(" ")
        network = modifier_data
        fulluser = word[0]
        command = word[1].upper()
        target = word[2]
        message = " ".join(word[3:]).lstrip(":")
        speaker = self.get_nick(fulluser)
        msg_obj = self.key_manager.decrypt(message,speaker,network)
        debug("server_message: %r" % msg_obj)
        if msg_obj:
            string = "%s %s %s :%s" % (fulluser,command,target,msg_obj.message)
            debug("message string: %r" % string)

            if msg_obj.to_network and command == "NOTICE":
                weechat.command(network,'/QUOTE NOTICE %s :%s' % (speaker,msg_obj.to_network))
        return string

    def prnt_message(self,data,buffer,date,tags,displayed,highlight,prefix,message):
        debug ("prnt_message",data=data,buffer=buffer,date=date,tags=tags,displayed=displayed,highlight=highlight,prfix=prefix,message=message)
        displayed=0
        return weechat.WEECHAT_RC_OK

    def out_message(self,data, modifier, modifier_data, string):
        return string

    def cmd_handler(self,data, buffer, args):
        debug ("cmd_handler",data=data,buffer=buffer,args=args)
        ## compatibility with xchat
        word = [data]
        if len(args) > 0:
            args = args.split(" ")
            word += args
        network = weechat.buffer_get_string(buffer, "localvar_server")
        target = weechat.buffer_get_string(buffer, "localvar_channel")
        debug("target,network,word: %r %r %r" % (target,network,word))
        if data == "KEYX":
            if len(word) > 1:
                target = word[1]
            return self.cmd_keyx(target,network,buffer)

        return weechat.WEECHAT_RC_OK

    def cmd_keyx(self,target,network,buffer):
        debug("cmd_keyx:",target=target,network=network,buffer=buffer)
        if not VALID_IRC_TARGET_RE.match(target):
            debug("cmd_msg: no valid irc target")
            return weechat.WEECHAT_RC_ERROR

        ## FIXME chan notice - what should happen when keyx is send to channel trillian seems to accept it and send me a key --
        if target.startswith("#"):
            prnt (_("Channel Exchange not implemented"))
            return weechat.WEECHAT_RC_ERROR

        msg_obj = self.key_manager.key_exchange(target,network)

        if msg_obj.message:
            prnt("%s\tNotice: %s" % (target,msg_obj.message))

        if not msg_obj.to_network:
            return weechat.WEECHAT_RC_OK
        
        ## send key with notice to target
        debug("sending %r" %'QUOTE NOTICE %s %s' % (target, msg_obj.to_network))
        weechat.command(network,'/QUOTE NOTICE %s %s' % (target, msg_obj.to_network))
        return weechat.WEECHAT_RC_OK

    def __del__(self):
        weechat.prnt("", _("\x19*03,00 fishcrypt.py successful unloaded"))


class MalformedError(Exception):
    pass


class block_cipher(object):
    blocksize = 8
    def pad(self,data):
         data = "%s%s" % (data,'\x00' * (self.blocksize - len(data) % self.blocksize))
         assert len(data) % self.blocksize == 0
         return data

    def fix_padding(self,data):
        pad_err = len(data) % self.blocksize
        if pad_err:
            debug("block_cipher: padding_error: len:%r  %r" % (len(data),pad_err))
            cut = (pad_err)*-1
            data = data[:cut]
        return data

class Blowfish(block_cipher):
    def __init__(self, key):
        self.blowfish = cBlowfish.new(key)

    def decrypt(self, data):
        return self.decrypt_mode(
            self.blowfish.decrypt,
                self.fix_padding(data)
            ).strip('\x00')

    def encrypt(self, data):
        debug ("Blowfish.encrypt: %r" % data)
        return self.encrypt_mode(self.blowfish.encrypt,self.pad(data))

    def decrypt_mode(self,func, data):
        return func(data)

    def encrypt_mode(self,func, data):
        return func(data)

class BlowfishCBC(Blowfish):
    def encrypt_mode(self,func, data):
        """The CBC mode. The randomy generated IV is prefixed to the ciphertext.
        'func' is a function that encrypts data in ECB mode. 'data' is the
        plaintext. 'blocksize' is the block size of the cipher."""
        assert len(data) % self.blocksize == 0
        IV = os.urandom(self.blocksize)
        assert len(IV) == self.blocksize
        ciphertext = IV
        while data:
            xored = xorstring(data[:self.blocksize], IV)
            enc = func(xored)
            ciphertext += enc
            IV = enc
            data = data[self.blocksize:]
        assert len(ciphertext) % self.blocksize == 0
        return ciphertext


    def decrypt_mode(self,func, data):
        """See cbc_encrypt."""
        assert len(data) % self.blocksize == 0
        
        IV = data[0:self.blocksize]
        data = data[self.blocksize:]

        plaintext = ''
        while data:
            text = func(data[0:self.blocksize])
            plaintext += xorstring(text, IV)
            IV = data[0:self.blocksize]
            data = data[self.blocksize:]
        assert len(plaintext) % self.blocksize == 0
        return plaintext


## blowcrypt, Fish etc.
# XXX: Unstable.
def blowcrypt_b64encode(s):
    """A non-standard base64-encode."""
    B64 = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    res = []
    while s:
        left, right = struct.unpack('>LL', s[:8])
        for i in xrange(6):
            res.append( B64[right & 0x3f] )
            right >>= 6
        for i in xrange(6):
            res.append( B64[left & 0x3f] )
            left >>= 6
        s = s[8:]
    return "".join(res)

def blowcrypt_b64decode(s):
    """A non-standard base64-decode."""
    B64 = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    res = []
    while s:
        left, right = 0, 0
        for i, p in enumerate(s[0:6]):
            right |= B64.index(p) << (i * 6)
        for i, p in enumerate(s[6:12]):
            left |= B64.index(p) << (i * 6)
        res.append( struct.pack('>LL', left, right) )
        s = s[12:]
    return "".join(res)


class dh1080_token(object):
    def __init__(self,private,public):
        self.private = private
        self.public = public
        self.remote_public = 0
        self.state = 0
        self.secret = 0
        self.expires = int(time.time()) + 60

    def get_secret(self):
        return self.secret

## DH1080
class dh1080_manager(object):
    def __init__(self):
        self.g_dh1080 = 2
        #self.p_dh1080 = int('FBE1022E23D213E8ACFA9AE8B9DFADA3EA6B7AC7A7B7E95AB5EB2DF858921FEADE95E6AC7BE7DE6ADBAB8A783E7AF7A7FA6A2B7BEB1E72EAE2B72F9FA2BFB2A2EFBEFAC868BADB3E828FA8BADFADA3E4CC1BE7E8AFE85E9698A783EB68FA07A77AB6AD7BEB618ACF9CA2897EB28A6189EFA07AB99A8A7FA9AE299EFA7BA66DEAFEFBEFBF0B7D8B', 16)
        self.p_dh1080 = self.string_to_long(self.b64decode("++ECLiPSE+is+proud+to+present+latest+FiSH+release+featuring+even+more+security+for+you+++shouts+go+out+to+TMG+for+helping+to+generate+this+cool+sophie+germain+prime+number++++/C32L"))
        self.q_dh1080 = (self.p_dh1080 - 1) / 2 
        self.bits = 1080
        self.db = {}

    def string_to_long(self,s):
        return long(binascii.hexlify(s),16)

    def make_hex_even(self,x):
        ##fix missing zero and make hexstring even
        return  len(x) % 2 == 0 and x or "0%s" % x

    def long_to_string(self,n):
        return binascii.unhexlify(self.make_hex_even("%.2x" % n))

    def sha256(self,s):
        return hashlib.sha256(s).digest()

    def b64decode(self,s):
        s_len = len(s)
        if s_len % 4 == 1 and s.endswith("A"):
            s = s[:-1]
        s = "%s%s" % (s,"="*(4-(s_len % 4)))
        return s.decode("base64")

    def b64encode(self,s):
        s = s.encode("base64")
        s = s.replace("\n","")
        if not s.endswith("="):
            s = "%sA" % s
        return s.replace("=","")

    def dh_validate_public(self,publickey):
        """See RFC 2631 section 2.1.5."""
        return 1 == pow(publickey, self.q_dh1080, self.p_dh1080)

    def set_remote_pub_key(self,target,remote_public_key):
        debug("set_remote_pub_key %r" % remote_public_key)
        token = self.db.get(target)
        if not token:
            raise CryptoError(_("No such target %r") % target)
        if not 1 < remote_public_key < self.p_dh1080:
            raise MalformedError
        if not self.dh_validate_public(remote_public_key):
            prnt(_("Key does not validate per RFC 2631. This check is not performed by any DH1080 implementation, so we use the key anyway. See RFC 2785 for more details."))
        token.remote_public = remote_public_key

    def get_secret(self,target):
        token = self.db.get(target)
        if not token:
            raise CryptoError(_("No such target %r") % target)
        assert token.remote_public > 0
        if token.expires > time.time():
            token.secret = pow(token.remote_public, token.private,self.p_dh1080)
            _key = self.b64encode(
                self.sha256(
                    self.long_to_string(token.secret)
                )
            )
        else:
            prnt("DH1080 exchange Token expired")
            _key = None
        del token
        debug("token_db: %r" % self.db)
        return _key

    def gen_keypair(self,target):
        private = 0
        public = 0
        debug("dh1080.gen_keypair")
        while True:
            private = self.string_to_long(os.urandom(self.bits/8))
            public = pow(self.g_dh1080, private, self.p_dh1080)
            if 2 <= public <= self.p_dh1080 - 1 and self.dh_validate_public(public) == 1:
                break
        token = dh1080_token(private,public)
        self.db[target] = token
        return token

    def destroy(self,target):
        try:
            del self.db[target]
        except KeyError:
            ## should not happen
            debug("ERROR: key %r was previously destroyed" % target)
            pass
        debug("debug_destroy: %r" % self.db)

    def pack(self,prefix,token):
        return "%s %s" % (prefix,self.b64encode(self.long_to_string(token.public)))

    def unpack(self,message):
        #debug("dh1080unpack: %r" % message)
        return self.string_to_long(self.b64decode(message))



def destroy_client_interface(userdata=None):
    global CLIENTINTERFACE
    #for k,v in globals().iteritems():
    #    if str(v).find("object") > -1: 
    #        prnt ("%-20s %s" % (k,v))

    del CLIENTINTERFACE
    return False


if  __name__ == "__main__":
    try:
        import xchat
        def get_query_context(name):
            for c in xrange(2):
                if len(name) == 0:
                    name = None
                ctx = xchat.find_context(channel=name)
                if ctx:
                    return ctx
                try:
                    setTabsetting = xchat.get_prefs('tab_new_to_front')
                    xchat.command("SET -quiet tab_new_to_front 0")
                    xchat.command("QUERY %s" % (name,))
                finally:
                    xchat.command("SET -quiet tab_new_to_front %s" % setTabsetting)
            return None
        def prnt(msg,tochannel=''):
            ctx = get_query_context(tochannel)
            if not ctx:
                print debug_message
            else:
                ctx.prnt(str(msg))

        __module_name__ = SCRIPT_NAME
        __module_version__ = SCRIPT_VERSION
        __module_description__ = SCRIPT_DESC
        CLIENTINTERFACE = xchat_client_interface()
    except ImportError:
        try:
            import weechat
            def prnt(msg,tochannel=''):
                buf = weechat.buffer_search('python',tochannel)
                if not buf:
                    buf = weechat.buffer_new(tochannel,"","","","")
                weechat.prnt(buf,"%s" % msg)
            CONFIG_FILE_NAME = SCRIPT_NAME
            CLIENTINTERFACE = weechat_client_interface()
            def weechat_unload_helper():
                return CLIENTINTERFACE.unload_interface()

            def weechat_server_message_helper(data, modifier, modifier_data, string):
                return CLIENTINTERFACE.server_message(data, modifier, modifier_data, string)

            def weechat_prnt_message_helper(data,buffer,date,tags,displayed,highlight,prefix,message):
                return CLIENTINTERFACE.prnt_message(data,buffer,date,tags,displayed,highlight,prefix,message)

            def weechat_outmessage_helper(data, modifier, modifier_data, string):
                return CLIENTINTERFACE.out_message(data, modifier, modifier_data, string)
            
            def weechat_command_helper(data, buffer, args):
                return CLIENTINTERFACE.cmd_handler(data, buffer,args)

        except ImportError:
            sys.exit("should be run from xchat or weechat with python enabled")

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4