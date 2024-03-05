
#用于计算哈希
import hashlib
#用于文件名替换
import re
import time

from datetime import datetime
from django.http import JsonResponse
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render
from django.shortcuts import redirect
from django.core.files.storage import FileSystemStorage

#Dynamic load dev version of qiling
import sys
from importlib import util
from os.path import basename
from os.path import exists
from types import ModuleType


def load_package_from_path(pkg_path: str) -> ModuleType:
    """
    ref: https://stackoverflow.com/a/50395128
    """
    try:
        init_path = f'{pkg_path}/__init__.py'
        assert exists(init_path)
        name = basename(pkg_path)
        
        spec = util.spec_from_file_location(name, init_path)
        module = util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    except:
        return None
    return module

load = load_package_from_path  # short alias
qiling = load(r'E:\Projects\scriptmalsolver\qiling\qiling')

using_public_code = False
if(qiling == None):
    using_public_code = True
    from qiling import *
#########################################33

from backend import utils
def upload_file(request):
    if request.method == 'POST' and request.FILES:
        uploaded_files = request.FILES.getlist('files')
        fileProperties = []
        for file in uploaded_files:
            # 读取文件内容并计算哈希值
            info = {
                'name' : file.name,
                'size' : file.size,
                'time' : datetime.now(),
                'content_type' : file.content_type,
                'hash' : hashlib.sha256(file.read()).hexdigest(),
                'report' : report_file(file)
            }
            fileProperties.append(info)
        return JsonResponse({'fileProperties': fileProperties})
    else:
        return JsonResponse({'error': '请上传文件'}, status=400)

def test_qiling(request):
    argv = [r'E:\Projects\scriptmalsolver\rootfs\x8664_windows\bin\hello.exe']
    rootfs = r'E:\Projects\scriptmalsolver\rootfs\x8664_windows'
    #verbose = qiling.QL_VERBOSE.DEBUG
    ql = qiling.Qiling(argv=argv, rootfs=rootfs, log_file = "log_qiling.log", verbose = 4)
    #ql = qiling.Qiling(argv=argv, rootfs=rootfs)
    ql.run()
    return JsonResponse({'result' : 'OK'})

def home(request):
    return redirect('login')
def login(request):
    LoadWallpaper = False
    if(request.method == "GET"):
        if(LoadWallpaper):
            wallpaperHelper = utils.bingWallpaperHelper()
            url_photo=wallpaperHelper.GetWallpaper()
            request.session['url_photo']=url_photo
        return render(request,"login.html")
    username = request.POST.get('user')
    password = request.POST.get('password')

    #Insecure login verfication
    # will be done.
    if(username == "root" and password == "toor"):
        return redirect('/index')
    return render(request, "login.html", {"error_msg" : "Incorrect username or password"})

def index(request):
    submit=[
        {'time' : '2024-3-3 17:33:45.3333',
         'filename' : 'rock_you!.zip',
         'size':'166 KB',
         'sha256':'N/A'},
        {'time' : '2024-3-4 20:55:45.4444',
         'filename' : 'rock_you2!.zip',
         'size':'166 KB',
         'sha256':'N/A'},
        {'time' : '2024-3-5 20:33:17.5555',
         'filename' : 'rock_you3!.zip',
         'size':'166 KB',
         'sha256':'N/A'},
    ]
    return render(request, "index.html",{'submit_list' : submit})

def submit(request):
    msg = {
        'msg' : ['上传参数错误'],
        'succeed' : False
    }
    #判定请求方法
    if request.method == 'POST':
        if request.FILES:
            #获取文件列表
            uploaded_files = request.FILES.getlist('file')

            #供测试
            print(uploaded_files)

            #判断文件为空?
            if(len(uploaded_files) == 0):
                return render(request, 'index.html', {'msg': msg})
            #如果文件列表不为空，则清除原先设定的错误消息。
            msg['msg'] = []


            #对文件列表内的文件执行操作。
            for file in uploaded_files:
                # 检查文件大小是否小于10MB
                if file.size <= 10 * 1024 * 1024:  
                    sha256 = hashlib.sha256()
                    for chunk in file.chunks():
                        sha256.update(chunk)
                    file_hash = sha256.hexdigest()
                    original_file_name, file_extension = file.name.split('.')[-2], file.name.split('.')[-1] 

                    timestamp = str(int(time.time()))
                    # 替换非a-zA-Z0-9字符为下划线
                    new_file_name = re.sub(r'[^a-zA-Z0-9]', '_', file_hash) + '_' + original_file_name + '_' + timestamp + '.'+ file_extension
                    fs = FileSystemStorage()
                    fs.save(new_file_name, file)
                else:
                    msg['msg'].append('文件 ' + file.name + ' 大小超过限制')
                    #return render(request, 'index.html')
            msg['succeed'] = True
            #如果未报错
            if(len(msg['msg']) == 0):
                msg['msg'] = '文件成功上传'

            return render(request, 'index.html', {'msg': msg})
    
    return render(request, 'index.html')