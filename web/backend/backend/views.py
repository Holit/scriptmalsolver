
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
import django


#动态加载qiling
import sys
from importlib import util
from os.path import basename
from os.path import exists
from types import ModuleType

def load_package_from_path(pkg_path: str) -> ModuleType:
    """
    从指定路径加载包
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

#指定qiling作为全局包
global qiling 
qiling = load_package_from_path(r'E:\Projects\scriptmalsolver\src\qiling\qiling')

#指定是否使用公共代码
using_public_code = False
if(qiling == None):
    using_public_code = True
    from qiling import *
#########################################
    
import os

from backend import utils
from .utils import *
from  .scanner.profile import *


def login(request):
    '''
    登录页面
    '''
    LoadWallpaper = False
    if(request.method == "GET"):
        #获取是否加载壁纸
        if(LoadWallpaper):
            url_photo=bingWallpaperHelper.GetWallpaper()
            request.session['url_photo']=url_photo
        return render(request,"login.html")
    elif(request.method == "POST"):
        username = request.POST.get('username')
        password = request.POST.get('password')
        print(f'username = {username}, password = {password}')
        #如果用户名和密码正确
        if(username == "root" and password == "toor"):
            return redirect('/submit')
        return render(request, "login.html", {"error_msg" : "用户名或密码错误"})
    
def index(request):
    return render(request, "index.html")

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
                #'report' : report_file(file)
            }
            fileProperties.append(info)
        return JsonResponse({'fileProperties': fileProperties})
    else:
        return JsonResponse({'error': '请上传文件'}, status=400)
    
def upload(request):
    upload_message = {
        'msg' : '上传参数错误',
        'succeed' : False
    }
    if(request.method == 'POST'):
        if(request.FILES):
            uploaded_file = request.FILES['file']
            if(uploaded_file.size > 10 * 1024 * 1024):
                upload_message['msg'] = '文件大小超过限制'
                return render(request, "index.html", {'upload_message' : upload_message})
            else:
                fs = FileSystemStorage()
                fs.save(uploaded_file.name, uploaded_file)
                upload_message['msg'] = '文件上传成功'
                upload_message['succeed'] = True
                return render(request, "analyze.html", {'upload_message' : upload_message})
    return
def setup_analyze(request,file_path):
    if request.method=='POST':
        if file_path and os.path.exists(file_path):
            from .scanner.analyzer import Analyzer
            analyzer = Analyzer(file_path)
            from .scanner.profile import QilingProfile
            _profile = QilingProfile()
            from .report import Report
            report = Report(file_path)
            general_info = report.get_general_info()

            return render(request, "analyze.html", {
                'general_info':general_info,
                'supported_lang_id':QilingProfile.get_supported_langid(),
                'supported_rootfs':QilingProfile.get_supported_roofs(),
                })
        return HttpErrorPage(request, 500, '文件不存在')
    return HttpErrorPage(request, 500, '错误的请求方法')
    
def analyze(request):
    return HttpErrorPage(request, 500, '未实现的功能')
    

# 需要重新设计submitted_files的结构。
# 考虑将其写入文件或者数据库。
submitted_files = []
def submit(request):
    msg = {
        'msg' : ['上传参数错误'],
        'succeed' : False
    }
    #判定请求方法
    if request.method == 'POST':
        if request.FILES:
            uploaded_file = request.FILES['file']
            if uploaded_file.size > 10 * 1024 * 1024:
                msg['msg'] = ['文件大小超过限制']
                return render(request, 'index.html', {'msg': msg})
            else:
                fs = FileSystemStorage()
                #将文件名中的所有非字母数字字符替换为下划线
                uploaded_file.name = re.sub(r'[^a-zA-Z0-9]', '_', uploaded_file.name)
                fs.save(uploaded_file.name, uploaded_file)
                #获取保存后的文件路径
                
                path = fs.path(uploaded_file.name)
                msg['msg'] = ['文件上传成功']
                msg['succeed'] = True
                return setup_analyze(request, path)

    elif request.method == 'GET':
        return HttpErrorPage(request, 500,'错误的请求方法')
    return render(request, 'submit.html')
def submit_multiple(request):
    
    return HttpErrorPage(request, 500, '未实现的功能')
    msg = {
        'msg' : ['上传参数错误'],
        'succeed' : False
    }
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
                print(f'type(file) = {type(file)}')
                # 检查文件大小是否小于10MB
                if file.size <= 10 * 1024 * 1024:  
                    try:
                        new_file_name, file_info = get_file_info(file)  
                    except ValueError as e:
                        msg['msg'].append(str(e))
                        continue
                    except Exception as e:
                        raise e
                    fs = FileSystemStorage()
                    fs.save(new_file_name, file)
                    
                    #写入数据库                
                    submitted_files.append(
                        file_info
                    )
                else:
                    msg['msg'].append('文件 ' + file.name + ' 大小超过限制')
            msg['succeed'] = True
            #如果未报错
            if(len(msg['msg']) == 0):
                msg['msg'] = ['文件成功上传']
            return render(request, 'submit.html', {
                'msg': msg,
                'submit_list' : submitted_files})
    pass
from .report import Report
def report(request):
    # 获取问号传递的参数
    hash = request.GET.get('hash')
    # 如果是测试用的哈希值，则返回测试报告
    if(hash == '1234'):
        return render(request, 'report.html', {'info' : Report.return_example_report_info(),
                                               'hash' : hash,
                                               'real_file_name' : 'example.exe'})
    global submitted_files
    submitted_files = scan_media_folder()
    
    file_info = next((info for info in submitted_files if info['sha256'] == hash), None)
    if(file_info == None):
        return HttpErrorPage(request, 500, '获取报告时发生错误:文件不存在')
    report = Report(file_info['path'])
    report.get_general_info(upload_time=file_info['time'])

    return render(request, 'report.html', {'info' : report.construct_report(),
                                            'hash' : hash,
                                            'real_file_name' : file_info['filename'].split('_')[-3] + '.' + file_info['filename'].split('_')[-1]})


def scan_media_folder():
    '''
    扫描media文件夹，并且对文件夹下所有文件都执行get_file_info操作，写入submitted_files
    '''
    import os
    runtime_folder = get_runtime_folder()
    media_folder = runtime_folder + '\\media'
    
    global submitted_files
    submitted_files = []

    for root, dirs, files in os.walk(media_folder):
        if(len(files) == 0):
            raise FileNotFoundError('media文件夹为空')
        for file in files:
            file_path = os.path.join(root, file)
            
            file_info = get_file_info(file_path ,rename_needed=False)
            submitted_files.append(file_info)

    return submitted_files

def get_file_info(file, rename_needed=True):
    '''
    获取文件信息
    file : str : 文件路径
    file : 文件对象（请执行错误处理）
    '''
    
    if(type(file) == str):

        import os
        # 检查文件是否存在
        if(os.path.exists(file) == False):
            raise FileNotFoundError('获取文件信息发生错误：文件不存在')
        # 计算文件哈希值
        file_hash = ''
        with open(file, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
            f.seek(0)
        # 检查是否存在相同哈希值的文件
        if file_hash in [info['sha256'] for info in submitted_files]:
            raise ValueError('存在相同哈希值的文件')
        
        _, filename = os.path.splitext(file)
        
        file_info = {
            'time' : datetime.now(),
            'filename' : os.path.basename(file),
            'size' : os.path.getsize(file),
            'sha256' : file_hash,
            'path' : file
        }
        if(rename_needed == False):
            return file_info
        
        # 获取文件名和扩展名
        filename_structure = filename.split('.')
        original_file_name, file_extension = '',''
        if(len(filename_structure) >= 2):
            original_file_name, file_extension = filename.split('.')[-2], filename.split('.')[-1]

        # 获取当前时间戳
        timestamp = str(int(time.time()))

        # 替换非a-zA-Z0-9字符为下划线，构建新文件名
        new_file_name =  file_hash[8:32+8] + '_' + re.sub(r'[^a-zA-Z0-9]', '_', original_file_name) + '_' + timestamp + '_'+ file_extension

        return new_file_name,file_info
    else:
        try:
            sha256 = hashlib.sha256()
            for chunk in file.chunks():
                sha256.update(chunk)
            file_hash = sha256.hexdigest()
            if file_hash in [info['sha256'] for info in submitted_files]:
                raise ValueError(f'存在相同哈希值的文件\n{file.name}\n{file_hash}')
            
            if(rename_needed == False):
                return file_info
            
            # 获取文件名和扩展名
            filename_structure = filename.split('.')
            original_file_name, file_extension = '',''
            if(len(filename_structure) >= 2):
                original_file_name, file_extension = filename.split('.')[-2], filename.split('.')[-1]

            # 获取当前时间戳
            timestamp = str(int(time.time()))

            # 替换非a-zA-Z0-9字符为下划线，构建新文件名
            new_file_name =  file_hash[8:32+8] + '_' + re.sub(r'[^a-zA-Z0-9]', '_', original_file_name) + '_' + timestamp + '_'+ file_extension

            file_info = {
                'time' : datetime.now(),
                'filename' : file.name,
                'size' : file.size,
                'sha256' : file_hash,
                'path' : f'media\\{new_file_name}'
            }
            
            return new_file_name,file_info
        except Exception as e:
            raise ValueError('获取文件信息发生错误：' + str(e))
        
