#!/usr/local/bin/python3
# coding:  utf-8

import fire
import sys
import os
from dotenv import load_dotenv
from utils import Fake115Client


class Main:
    def __init__(self, targetpath=None, c=None, cid=None, cookies=None, free=None):
        self._targetpath = targetpath or '.'
        self._cid = c if c is not None else (cid if cid is not None else 0)
        self._free = free or False
        # 加载.env文件
        load_dotenv()
        # 读取COOKIE变量
        self._cookies = cookies or os.getenv('COOKIE', 'need your cookie')

        print(self._cookies)

        if self._targetpath == None:
            print("请传入targetpath作为目标路径", sys.stderr)
            input("按任意键结束...")
            sys.exit()

        self.cli = Fake115Client.Fake115Client(self._cookies)

        self.test()

        if self._cid != None:
            self.cli.cid = self._cid
            self.cli.show_folder_path()

    def test(self):
        if self.cli.user_key == None:
            print("获取UserKey失败，请检查Cookie的有效性！", sys.stderr)
            sys.exit()

    def uploadf(self, targetpath=None, ef: bool = False, empty_folder: bool = False):

        # 使用not对布尔值进行取反
        _ignore_empty_folders = not (ef or empty_folder)
        _targetpath = targetpath or self._targetpath

        self.cli.upload_directory(
            _targetpath, free=self._free, ignore_empty_folders=_ignore_empty_folders)

    def upload(self, filename):
        if filename == None:
            # usage()
            input("按任意键结束...")
            return

        self.cli.upload_file(filename, free=self._free)

    def infile(self, filename):
        if filename == None:
            # usage()
            input("按任意键结束...")
            return

        self.cli.import_file_from_link(filename)

    def export(self, filename):
        if filename == None:
            # usage()
            input("按任意键结束...")
            return

        self.cli.export_link_to_file(filename, self.cid)
        print('Total file count :', self.cli.filecount)

    def build(self, filename):
        if filename == None:
            # usage()
            input("按任意键结束...")
            return

        self.cli.build_links_from_disk(filename)


if __name__ == '__main__':
    fire.Fire(Main)
