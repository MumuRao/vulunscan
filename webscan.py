#coding:utf-8
#python3

import os
import sys
import warnings
from lib.consle_width import getTerminalSize
import time

sys.path.append(sys.path[0] + '/web_script')
sys.path.append(sys.path[0] + "/../")

warnings.filterwarnings("ignore")    #忽略报错输出
script_path = sys.path[0] + '/web_script'



class WebScan():
    def __init__(self, path, url):
        self.path = path
        self.url = url
        self.script_count = self.scan_count = self.Vulun_count = 0
        self.console_width = getTerminalSize()[0] - 2
        self.local_time = time.time()

    def script(self):
        for root, dirs, files in os.walk(self.path):  
            return files

    def scan(self):
        TIMEOUT = 10
        files = self.script()
        self.script_count = len(files)
        for script_file in files:
            if script_file.split('.')[1] == "py":
                script_import = script_file.split('.')[0]
                script_res = __import__(script_import)
                result_info = script_res.check(self.url, self.port, TIMEOUT)
                self.scan_count += 1
                if result_info:
                    self.Vulun_count += 1
                    msg = result_info
                    self._print_msg(msg, _found_msg=True)
                    self._print_msg()
                    # self.outfile.write(cur_sub_domain.ljust(30) + '\t' + ips + '\n')
                    # self.outfile.flush()
                else : 
                    self._print_msg()
            else : pass
            
    def _print_msg(self, _msg=None, _found_msg=False):
        if _msg is None:
            msg = '%s Vulun| %s scanned in %.1f seconds| All %s scripts' % (
                self.Vulun_count, self.scan_count, time.time() - start_time, self.script_count)
            sys.stdout.write('\r' + ' ' * (self.console_width - len(msg)) + msg)
        else:
            sys.stdout.write('\r' + _msg + ' ' * (self.console_width - len(_msg)) + '\n')
            if _found_msg:
                msg = '%s Found| %s Groups| %s scanned in %.1f seconds' % (
                    self.found_count, self.queue.qsize(), self.scan_count, time.time() - self.start_time)
                sys.stdout.write('\r' + ' ' * (self.console_width - len(msg)) + msg)
        sys.stdout.flush()


if __name__ == '__main__':
    start_time = time.time()
    WebScan(script_path,'http://127.0.0.1').scan()