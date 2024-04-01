import json
import urllib.request as ur
import random
class bingWallpaperHelper(object):
    '''
    获取bing壁纸的工具类
    '''
    @staticmethod
    def GetWallpaper(self):
        '''
        获取bing壁纸的url
        '''
        url=r'http://cn.bing.com/HPImageArchive.aspx?format=js&idx=0&n=2'
        headers={
            'User-Agent': 'Mozilla / 4.0(compatible;MSIE6.0;Windows NT 5.1)'
        }
        request=ur.Request(url,headers=headers)
        response=ur.urlopen(request)
        html_byte=response.read()
        html_string=html_byte.decode('utf-8')
        #解析成字典形式,图片保存在images的key中:
        dict_json=json.loads(html_string)
        #得到images的key所包含的图片信息:
        list_photo=dict_json['images']
        #得到list_photo中的第三张图片组成的字典
        dict_three=list_photo[2]
        #得到图片的残缺url
        url_photo=dict_three['url']
        #将图片的残缺url组合成一个完整的url
        url_photo=r'http://cn.bing.com'+url_photo
        return url_photo

def compute_crc32(file_path):
    '''
    计算文件的crc32值
    '''
    import zlib
    with open(file_path, 'rb') as file:
        data = file.read()
        crc = zlib.crc32(data)
        return hex(crc & 0xFFFFFFFF)[2:].upper()

def get_runtime_folder():
    '''
    获取运行时文件夹
    'E:\\Projects\\scriptmalsolver\\src\\web\\backend'
    '''
    import os
    dir = os.path.split(__file__)[0]
    basedir = os.path.split(dir)[0]
    return basedir

def test_qiling(request):
    '''
    测试qiling组件可用性
    '''
    argv = [r'E:\Projects\scriptmalsolver\rootfs\x8664_windows\bin\hello.exe']
    rootfs = r'E:\Projects\scriptmalsolver\rootfs\x8664_windows'
    #verbose = qiling.QL_VERBOSE.DEBUG
    ql = qiling.Qiling(argv=argv, rootfs=rootfs, log_file = "log_qiling.log", verbose = 4)
    #ql = qiling.Qiling(argv=argv, rootfs=rootfs)
    ql.run()
    return JsonResponse({'result' : 'OK'})

from django.http import HttpResponse
from django.shortcuts import render

def HttpErrorPage(request, statusCode, msg):
    return render(request, 'error.html', {'statusCode': statusCode, 'msg': msg})
