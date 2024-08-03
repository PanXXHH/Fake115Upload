#!/usr/local/bin/python3
# coding:  utf-8

# import fire

from requests_toolbelt.multipart.encoder import MultipartEncoder
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.PublicKey import RSA
from Crypto import Random
from ecdsa import ECDH, NIST224p, SigningKey
from binascii import a2b_hex
import hashlib
import base64
import lz4.block
import zlib
import sys
import os
import time
import platform
import json
import requests
import random
import ctypes
import codecs
import urllib
from requests_toolbelt.multipart.encoder import MultipartEncoder, MultipartEncoderMonitor
import utils.upload_progress
from dataclasses import dataclass
from tqdm import tqdm


class Fake115Client(object):

    def __init__(self,  cookie):
        self.app_version = '25.2.2'
        self.api_version = '2.0.1.7'
        self.cookie = cookie
        self.ua = 'Mozilla/5.0;  Mac  OS  X/10.15.7;  115Desktop/2.0.1.7'
        self.content_type = 'application/x-www-form-urlencoded'
        self.header = {"User-Agent":  self.ua,
                       "Content-Type":  self.content_type,  "Cookie": self.cookie}
        self.crc_salt = '^j>WD3Kr?J2gLFjD4W2y@'
        self.md5_salt = 'Qclm8MGWUv59TnrR0XPg'
        self.remote_pubkey = '0457A29257CD2320E5D6D143322FA4BB8A3CF9D3CC623EF5EDAC62B7678A89C91A83BA800D6129F522D034C895DD2465243ADDC250953BEEBA'
        self.private_key = RSA.construct((0x8C81424BC166F4918756E9F7B22EFAA03479B081E61896872CB7C51C910D7EC1A4CE2871424D5C9149BD5E08A25959A19AD3C981E6512EFDAB2BB8DA3F1E315C294BD117A9FB9D8CE8E633B4962E087C629DC6CA3A149214B4091EF2B0363CB3AE6C7EE702377F055ED3CD93F6C342256A76554BBEA7F203437BBE65F2DA2741,
                                         0x10001,  0x3704DAB00D80C25E464FFB785A16D95F688D0A5823811758C16308D5A1DB55FA800D967A9B4AEDE79AA783ADFFDCDB23541C80B8D436901F172B1CCCA190B224DBE777BF18B96DD9A30AACE8780350793A4F90A645A7747EF695622EADBE23A4C6D88F22E87842B43B35486C2D1B5B1FA77DB3528B0910CA84EDB7A46AFDBED1))
        self.public_key = RSA.construct(
            (0x8686980c0f5a24c4b9d43020cd2c22703ff3f450756529058b1cf88f09b8602136477198a6e2683149659bd122c33592fdb5ad47944ad1ea4d36c6b172aad6338c3bb6ac6227502d010993ac967d1aef00f0c8e038de2e4d3bc2ec368af2e9f10a6f1eda4f7262f136420c07c331b871bf139f74f3010e3c4fe57df3afb71683,  0x10001))
        self.g_key_l = a2b_hex('7806AD4C33865D184C013F46')
        self.g_key_s = a2b_hex('2923215E')
        self.g_kts = a2b_hex('F0E569AEBFDCBF8A1A45E8BE7DA673B8DE8FE7C445DA86C49B648B146AB4F1AA3801359E26692C86006B4FA5363462A62A966818F24AFDBD6B978F4D8F8913B76C8E93ED0E0D483ED72F88D8FEFE7E8650954FD1EB832634DB667B9C7E9D7A8132EAB633DE3AA95934663BAABA816048B9D5819CF86C8477FF5478265FBEE81E369F34805C452C9B76D51B8FCCC3B8F5')
        self.curve = NIST224p
        self.m115_l_rnd_key = None
        self.m115_s_rnd_key = None
        self.local_private_key = None
        self.local_public_key = None
        self.aes_key = None
        self.aes_iv = None
        self.user_id = None
        self.user_key = None
        self.std_out_handle = None
        self.filecount = 0
        self.cid = "0"

        sk = SigningKey.generate(curve=self.curve)
        ecdh = ECDH(curve=self.curve)
        ecdh.load_private_key(sk)
        local_public_key = ecdh.get_public_key().to_string()

        self.local_public_key = b'\x29'+local_public_key
        ecdh.load_received_public_key_bytes(a2b_hex(self.remote_pubkey))
        secret = ecdh.generate_sharedsecret_bytes()
        self.aes_key = secret[0:16]
        self.aes_iv = secret[-16:]

        if self.get_userkey() is False:
            print('Get  userkey  info  failed!')

    def m115_init(self):
        self.g_key_l = a2b_hex('7806AD4C33865D184C013F46')
        self.g_key_s = a2b_hex('2923215E')

    def m115_setkey(self, randkey, sk_len):

        length = sk_len * (sk_len-1)
        index = 0
        xorkey = b''
        if randkey:
            for i in range(0, sk_len):
                x = (randkey[i] + self.g_kts[index]) & 0xff
                xorkey += chr((self.g_kts[length]) ^ x).encode('latin1')
                length -= sk_len
                index += sk_len

        if (sk_len == 4):
            self.g_key_s = xorkey
        elif (sk_len == 12):
            self.g_key_l = xorkey

    def xor115_enc(self, src, key):
        header = ''
        pad = len(src) % 4

        if pad > 0:
            for i in range(0, pad):
                header += chr((src[i]) ^ (key[i]))
            src = src[pad:]
        lkey = len(key)
        secret = []
        num = 0
        for s in src:
            if num >= lkey:
                num = num % lkey
            secret.append(chr((s) ^ (key[num])))
            num += 1

        return (header+"".join(secret))

    def m115_encode(self, plaintext):
        self.m115_init()
        self.m115_l_rnd_key = Random.new().read(16)
        self.m115_setkey(self.m115_l_rnd_key, 4)
        tmp = self.xor115_enc(plaintext.encode('latin1'), self.g_key_s)[::-1]
        xortext = self.xor115_enc(tmp.encode(
            'latin1'),  self.g_key_l).encode('latin1')
        cipher = PKCS1_v1_5.new(self.public_key)
        ciphertext = cipher.encrypt(self.m115_l_rnd_key+xortext)
        ciphertext = urllib.parse.quote(base64.b64encode(ciphertext))

        return ciphertext

    def m115_decode(self, ciphertext):
        key_size = 16
        block_size = 128
        plaintext = b''
        ciphertext = base64.b64decode(ciphertext)
        block = len(ciphertext)//block_size

        for i in range(0, block):
            m = long_to_bytes(pow(bytes_to_long(
                ciphertext[i*128:block_size]), self.public_key.e, self.public_key.n))
            m = m[m.index(b'\x00')+1:]
            plaintext += m
            block_size += 128

        self.m115_s_rnd_key = plaintext[0:key_size]
        plaintext = plaintext[key_size:]
        self.m115_setkey(self.m115_l_rnd_key, 4)
        self.m115_setkey(self.m115_s_rnd_key, 12)
        tmp = self.xor115_enc(plaintext, self.g_key_l)[::-1]
        plaintext = self.xor115_enc(tmp.encode('latin1'), self.g_key_s)
        return plaintext

    def ec115_get_token(self, data):  # md5(fileid+filesize+preid+uid+timestap+md5(uid))
        m = hashlib.md5()
        m.update(data)
        return m.hexdigest()

    def ec115_compress_decode(self, data):
        size = ord(data[0])+(ord(data[1]) << 8)
        return (lz4.block.decompress(data[2:size+2], 0x2000))

    def ec115_encode_data(self, data):
        mode = AES.MODE_ECB
        BS = AES.block_size
        def pad(s): return s + (BS - len(s) % BS) * chr(0)
        def unpad(s): return s[0:-ord(s[-1])]
        data = pad(data)
        cipher_text = ''
        xor_key = self.aes_iv
        tmp = ''

        cryptos = AES.new(self.aes_key,  mode)
        for i in range(0, len(data)):
            tmp += chr(ord(data[i]) ^ ord(xor_key[i % 16]))
            if ((i % 16) == 15):
                xor_key = cryptos.encrypt(tmp)
                cipher_text += xor_key
                tmp = ''

        return cipher_text

    def ec115_encode_token(self, timestap=None):
        r1 = random.randint(0x0, 0xff)
        r2 = random.randint(0x0, 0xff)
        tmp = ''

        try:
            for i in range(0, 15):
                tmp += chr(ord(self.local_public_key[i]) ^ r1)
            tmp += chr(r1)+chr(0x73 ^ r1)
            timestap = hex(timestap)[2:].decode('hex')

            for i in range(0, 3):
                tmp += chr(r1)
            for i in range(0, 4):
                tmp += chr(r1 ^ ord(timestap[3-i]))
            for i in range(15, 30):
                tmp += chr(ord(self.local_public_key[i]) ^ r2)
            tmp += chr(r2)+chr(1 ^ r2)
            for x in xrange(0, 3):
                tmp += chr(r2)

            crc = zlib.crc32(self.crc_salt+tmp) & 0xffffffff
            h_crc32 = hex(crc)[2:]
            if (len(h_crc32) % 2 != 0):
                h_crc32 = '0'+h_crc32
            h_crc32 = h_crc32.decode('hex')
            for i in range(0, 4):
                tmp += (h_crc32[3-i])

        except Exception as e:
            print(e)

        return base64.b64encode(tmp)

    def ec115_decode(self, data):
        BS = AES.block_size
        def pad(s): return s + (BS - len(s) % BS) * chr(0)
        def unpad(s): return s[0:-ord(s[-1])]
        cipher = AES.new(self.aes_key,  AES.MODE_CBC, self.aes_iv)
        lz4_buff = cipher.decrypt((data[0:-(len(data) % 16)]))

        return self.ec115_compress_decode(lz4_buff)

    def get_file_size(self, file):
        return str(os.path.getsize(file))

    def get_userkey(self):
        try:
            r = requests.get(
                "http://proapi.115.com/app/uploadinfo", headers=self.header)
            resp = json.loads(r.content)
            self.user_id = str(resp['user_id'])
            self.user_key = str(resp['userkey']).upper()
        except Exception as e:
            print("Explired  cookie  !", e)
            return False

    def show_folder_path(self):
        print('self.cid', self.cid)
        url = 'https://webapi.115.com/files?aid=1&cid='+str(self.cid) + \
            '&o=user_ptime&asc=0&offset=0&show_dir=1&limit=115&code=&scid=&snap=0&natsort=1&record_open_time=1&source=&format=json&type=&star=&is_q=&is_share='
        r = requests.get(url, headers=self.header)
        print('r.content', r.content)
        resp = json.loads(r.content)['path']
        path = '{'
        for f in resp:
            path += f['name']+'=>'
        path = path[:-2]+'}'
        self.log(path, False, "PATH")

    def get_preid(self, pickcode):

        file_url = self.get_download_url_by_pc(pickcode)

        token = self.cookie
        try:
            token = r.headers['Set-Cookie'].split(';')[0]
        except Exception as e:
            pass

        head = {"User-Agent":  self.ua,
                "Range": "bytes=0-131071", "Cookie": token}
        r2 = requests.get(file_url, headers=head)
        sha = hashlib.sha1()
        sha.update(r2.content)
        preid = sha.hexdigest()
        return preid.upper()

    def get_download_url_by_pc(self, pc):
        url = 'http://proapi.115.com/pc/ufile/downurl'
        pc_data = ('{"pickcode":"%s","app_ver":"%s"}') % (pc, self.api_version)
        data = 'data='+self.m115_encode(pc_data)
        r = requests.post(url,  data=data, headers=self.header)
        ciphertext = (json.loads(r.content)['data'])
        plaintext = self.m115_decode(ciphertext)
        jtext = json.loads(plaintext).items()

        for key,  value in jtext:
            url = value['url']['url']

        return url

    def get_link(self, filename):
        try:
            with open(filename, 'rb') as f:
                sha = hashlib.sha1()
                sha.update(f.read(1024*128))
                BlockHASH = sha.hexdigest().upper()
                f.seek(0, 0)
                sha = hashlib.sha1()
                sha.update(f.read())
                TotalHASH = sha.hexdigest().upper()
                link = filename+'|' + \
                    str(os.path.getsize(filename)) + \
                    '|'+TotalHASH+'|'+BlockHASH+'\n'
                return link
        except Exception as e:
            print(e)
            return

    def import_file_with_sha1(self, preid, fileid, filesize, filename):  # pc  api
        fileid = fileid
        target = 'U_1_'+str(self.cid)
        tm = int(time.time())
        s1 = hashlib.sha1((self.user_id+fileid+target +
                          '0').encode('utf8')).hexdigest()
        s2 = self.user_key+s1+"000000"
        sig = hashlib.sha1(s2.encode('utf8')).hexdigest().upper()

        h1 = hashlib.md5(self.user_id.encode('utf8')).hexdigest()
        token = hashlib.md5((self.md5_salt+fileid + filesize+preid+self.user_id +
                            str(tm)+h1+self.api_version).encode('utf8')).hexdigest()
        url = ("http://uplb.115.com/3.0/initupload.php?appid=0&appversion=%s&format=json&isp=0&sig=%s&t=%d&topupload=0&rt=0&token=%s") % (self.api_version, sig, tm, token)
        postData = ('fileid=%s&filename=%s&filesize=%s&preid=%s&target=%s&userid=%s') % (
            fileid,  filename,  filesize,  preid,  target,  self.user_id)

        r = requests.post(url,  data=(
            postData.encode('utf8')), headers=self.header)

        print("r.content", r.content)

        response = (r.content)

        try:
            if json.loads(response)['status'] == 2 and json.loads(response)['statuscode'] == 0:
                self.log(filename+'  upload  completed.', False, "OK")
                return True
            else:
                self.log(filename+'  upload  failed.', True, "ERROR")
                return False
        except Exception as e:
            print(e)
            return

    # mobile  api
    def import_file_with_sha1_android(preid,  fileid,  filesize,  filename):
        fileid = fileid.upper()
        quickid = fileid
        target = 'U_1_'+str(self.cid)
        hash = hashlib.sha1(
            (user_id+fileid+quickid+pickcode+target+'0')).hexdigest()
        a = userkey+hash+end_string
        sig = hashlib.sha1(a).hexdigest().upper()
        url = "http://uplb.115.com/3.0/initupload.php?isp=0&appid=0&appversion=" + \
            self.app_version+"&format=json&sig="+sig
        postData = {
            'preid': preid,
            'filename': filename,
            'quickid': fileid,
            'user_id': user_id,
            'app_ver': self.app_version,
            'filesize': filesize,
            'userid': user_id,
            'exif': '',
            'target': target,
            'fileid': fileid
        }
        r = requests.post(url,  data=postData, headers=header)
        try:
            if json.loads(r.content)['status'] == 2 and json.loads(r.content)['statuscode'] == 0:
                printInfo(filename+'  upload  completed.', False, "OK")
                return True
            else:
                printInfo(filename+'  upload  failed.', True, "ERROR")
                return False
        except:
            return False

    def upload_file_with_sha1(self, filename):
        self.log("Trying  fast  upload...", False, "INFO")
        with open(filename, 'rb') as f:
            sha1 = hashlib.sha1()
            sha1.update(f.read(1024*128))
            blockhash = sha1.hexdigest().upper()
            f.seek(0, 0)
            sha1 = hashlib.sha1()
            while True:
                data = f.read(64 * 1024)
                if not data:
                    break
                sha1.update(data)
            totalhash = sha1.hexdigest().upper()
            print(totalhash)
            ret = self.import_file_with_sha1(
                blockhash, totalhash, self.get_file_size(filename), os.path.basename(filename))
            return ret

    def export_link_to_file(self, outfile, cid):
        uri = "http://webapi.115.com/files?aid=1&cid=" + \
            str(cid)+"&o=user_ptime&asc=0&offset=0&show_dir=1&limit=5000&code=&scid=&snap=0&natsort=1&source=&format=json"
        url = 'http://aps.115.com/natsort/files.php?aid=1&cid=' + \
            str(cid)+'&o=file_name&asc=1&offset=0&show_dir=1&limit=5000&code=&scid=&snap=0&natsort=1&source=&format=json&type=&star=&is_share=&suffix=&custom_order=&fc_mix='

        resp = ''
        r = requests.get(uri, headers=self.header)
        if ('data' in json.loads(r.content)):
            resp = json.loads(r.content)['data']

        else:
            r = requests.get(url, headers=self.header)
            resp = json.loads(r.content)['data']

        of = codecs.open(outfile, 'a+',  encoding='utf-8')
        for d in resp:
            if 'fid' in d:

                self.filecount += 1
                try:
                    # print(d['pc'])
                    preid = self.get_preid(d['pc'])
                    self.log(d['n']+'|'+str(d['s'])+'|'+d['sha'] +
                             '|'+preid, False, str(self.filecount))
                    of.write(d['n']+'|'+str(d['s']) +
                             '|'+d['sha']+'|'+preid+'\n')
                except Exception as e:
                    print(e)
                    of.write(d['n']+'|'+str(d['s']) +
                             '|'+d['sha']+'|'+preid+'\n')
                continue
            elif 'pid' in d:
                cid = d['cid']
                self.export_link_to_file(outfile, cid)
        of.close()

    def import_file_from_link(self, file):    #
        for l in codecs.open(file, 'r', 'utf-8'):
            link = l.split('|')
            filename = link[0]
            filesize = link[1]
            fileid = link[2]
            preid = link[3].strip()
            if (len(fileid) != 40 and len(preid) != 40):
                print('Error  link!')
                return
            self.import_file_with_sha1(preid, fileid, filesize, filename)

    def upload_file(self, file_path, free=False, cid: str = None):
        # if self.upload_file_with_sha1(filename):
        #     return

        filename = os.path.basename(file_path)

        self.log("Trying  local  upload...", False, "INFO")

        uri = 'http://uplb.115.com/3.0/sampleinitupload.php'
        _cid = cid or self.cid
        print('_cid', _cid)

        postdata = {"userid": self.user_id, "filename": filename,
                    "filesize": self.get_file_size(file_path), "target": "U_1_"+str(_cid)}
        r = requests.post(uri, headers=self.header, data=postdata)
        resp = json.loads(r.content)

        with open(file_path, 'rb') as file:
            # 构建 MultipartEncoder 对象
            m = MultipartEncoder(
                fields={
                    "name": filename,
                    "key": resp['object'],
                    "policy": resp['policy'],
                    "OSSAccessKeyId": resp['accessid'],
                    "success_action_status": '200',
                    "callback": resp['callback'],
                    "signature": resp['signature'],
                    "file": (os.path.basename(file_path), file, "multipart/form-data")
                }
            )

            # 创建 MultipartEncoderMonitor 监控对象
            monitor = MultipartEncoderMonitor(
                m, callback=utils.upload_progress.upload_progress)

            # 发送 POST 请求，包含进度监控
            r = requests.post(resp['host'], data=monitor, headers={
                              'Content-Type': monitor.content_type})
            print('\n', r.content)
            # print("\n上传完成")
        try:
            if json.loads(r.content)['state'] == True and json.loads(r.content)['code'] == 0:
                self.log(os.path.basename(file_path) +
                         ' 文件已上传完成。', False, "OK")
                if free:
                    # 打开文件并清空内容
                    with open(file_path, 'wb') as file:
                        file.write(bytes(r.content))
                        pass  # 打开文件的写入模式会自动清空文件

                    # 构建新的文件名
                    new_file_path = file_path + ".uploaded"

                    # 重命名文件
                    os.rename(file_path, new_file_path)
                    self.log(os.path.basename(file_path) +
                             ' 文件已释放。', False, "OK")
            else:
                self.log(os.path.basename(file_path) +
                         '  upload  failed.', True, "ERROR")
        except Exception as e:
            self.log('error: %s' % e, True, "ERROR")
            return
            # print('error', e)

        return

    def upload_directory(self, target_path: str, free=False):

        _targetpath = os.path.abspath(target_path)
        # _free = free

        print('self._cid', self.cid)

        def dfs_walk(dir_path, parent_cid=None):

            dir_name = os.path.basename(dir_path)

            if parent_cid is None:  # 判断是否是顶层目录
                cid = self.cid  # 顶层目录的CID设为0
            else:
                print("正在尝试为多级目录创建远程文件夹...")
                ret = self.add_directory(
                    dir_name, base_directory_cid=parent_cid)

                if ret.isExist:
                    self.log('远程文件夹 %s 已存在！' % dir_name, False, "INFO")
                else:
                    self.log('远程文件夹 %s 创建成功！' % dir_name, False, "INFO")

                cid = ret.cid
                # cid = uuid.uuid4()  # 为当前目录生成一个随机的唯一标识符

            # 输出当前目录路径和CID
            print(f"当前目录: {dir_path} (CID: {cid}, 父目录CID: {parent_cid})")

            files = []  # 用于存放当前目录下的文件名
            directories = []  # 用于存放当前目录下的子目录名

            # 遍历当前目录，并分别存储文件和目录
            for entry in os.listdir(dir_path):
                full_path = os.path.join(dir_path, entry)
                if os.path.isdir(full_path):
                    directories.append(full_path)
                else:
                    files.append(entry)

            # 输出当前目录下的所有文件
            if files:
                print("包含的文件:")
                for file in tqdm(files, desc="正在对当前目录文件进行上传..."):
                    print(file)
                    self.upload_file(os.path.join(
                        dir_path, file), free=free, cid=cid)

            # 递归遍历子目录
            for directory in tqdm(directories, desc="正在递归遍历子目录..."):
                dfs_walk(directory, parent_cid=cid)  # 传递当前目录的CID作为子目录的父目录CID

        dfs_walk(_targetpath)

    def build_links_from_disk(self, outfile):
        self.log(os.getcwd(), False, 'PATH')
        files = os.listdir(os.getcwd())
        of = codecs.open(outfile, 'a+', 'utf-8')
        c = 0
        for f in files:
            c += 1
            if os.path.isfile(f):
                ret = self.get_link(f)
                self.log(ret, False, str(c))
                of.write(ret)
        of.close()

    def set_cmd_text_color(self, color):
        Bool = ctypes.windll.kernel32.SetConsoleTextAttribute(
            self.std_out_handle,  color)
        return Bool

    def resetColor(self):
        self.set_cmd_text_color(0x0c | 0x0a | 0x09)

    def log(self, info, erorr, notice=''):
        sysstr = platform.system()
        if erorr == True:
            if (sysstr == "Windows"):
                self.std_out_handle = ctypes.windll.kernel32.GetStdHandle(-11)
                self.set_cmd_text_color(0x0c)
                sys.stdout.write('['+notice+']  '+info+'\n')
                self.resetColor()
            else:
                print('\033[31m'+'['+notice+']  '+info)
        else:
            if (sysstr == "Windows"):
                self.std_out_handle = ctypes.windll.kernel32.GetStdHandle(-11)
                self.set_cmd_text_color(0x0a)
                sys.stdout.write('['+notice+']  '+info+'\n')
                self.resetColor()
            else:
                print('\033[32m'+'['+notice+']  '+info)

    def add_directory(self, name: str, base_directory_cid: int | str = "0"):

        _name = str(name)
        _base_directory_cid = str(base_directory_cid)
        __isExist: bool = None
        __cid: str = None

        @dataclass
        class __ReturnClass:
            isExist: bool
            cid: str

        headers = {
            "Cookie": self.cookie
        }

        # 表单数据
        params = {
            'pid': _base_directory_cid,
            'cname': _name
        }

        resp = requests.post("https://webapi.115.com/files/add",
                             data=params, headers=headers)

        print(resp.content)

        resp_json = json.loads(resp.content)

        if resp_json['state']:
            return __ReturnClass(isExist=False, cid=resp_json['cid'])
        elif resp_json['errno'] == 20004:  # 说明文件夹已存在

            __isExist = True

            # 遍历目录下文件，获得cid
            params = {
                'aid': '1',
                'cid': _base_directory_cid,
                'o': 'user_ptime',
                'asc': '0',
                'offset': '0',
                'show_dir': '1',
                'limit': '40',
                'code': '',
                'scid': '',
                'snap': '0',
                'natsort': '1',
                'record_open_time': '1',
                'count_folders': '1',
                'type': '',
                'source': '',
                'format': 'json',
                'star': '',
                'is_share': '',
                'suffix': '',
                'custom_order': '',
                'fc_mix': '',
            }

            resp = requests.get("https://webapi.115.com/files",
                                params=params, headers=headers)

            resp_json = json.loads(resp.content)

            for params in resp_json['data']:
                if 'ns' not in params:
                    continue  # 说明不是文件夹

                if params['ns'] == _name:
                    __cid = params['cid']
                    break

            if __cid is not None:
                return __ReturnClass(isExist=__isExist, cid=__cid)

        else:
            print(resp_json, sys.stderr)
            raise Exception("创建文件夹失败！未知错误！")

