import json
import urllib.request as ur
import random
class bingWallpaperHelper(object):

    def GetWallpaper(self):
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