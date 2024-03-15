
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
qiling = load(r'E:\Projects\scriptmalsolver\src\qiling\qiling')

using_public_code = False
if(qiling == None):
    using_public_code = True
    from qiling import *
#########################################33
import os

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
                #'report' : report_file(file)
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

    #从数据库中读取
    #Insecure login verfication
    # will be done.
    if(username == "root" and password == "toor"):
        return redirect('/index')
    return render(request, "login.html", {"error_msg" : "Incorrect username or password"})

submitted_files = []
def index(request):
    submitted_files = scan_media_folder()
    print(submitted_files)
    return render(request, "index.html",{'submit_list' : submitted_files})

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
                print(f'type(file) = {type(file)}')
                # 检查文件大小是否小于10MB
                if file.size <= 10 * 1024 * 1024:  
                    try:
                        new_file_name, file_info = get_file_info(file)  
                    except ValueError as e:
                        msg['msg'].append(str(e))
                        continue
                    fs = FileSystemStorage()
                    fs.save(new_file_name, file)
                    
                    #写入数据库                
                    submitted_files.append(
                        file_info
                    )
                else:
                    msg['msg'].append('文件 ' + file.name + ' 大小超过限制')
                    #return render(request, 'index.html')
            msg['succeed'] = True
            #如果未报错
            if(len(msg['msg']) == 0):
                msg['msg'] = ['文件成功上传']
            return render(request, 'index.html', {'msg': msg,'submit_list' : submitted_files})
    
    return render(request, 'index.html')

def report(request):
    # 获取问号传递的参数
    hash = request.GET.get('hash')
    # 如果是测试用的哈希值，则返回测试报告
    if(hash == '1234'):
        return render(request, 'report.html', {'info' : return_example_report_info(),
                                               'hash' : hash,
                                               'real_file_name' : 'example.exe'})

    submitted_files = scan_media_folder()
    print(submitted_files)
    file_info = next((info for info in submitted_files if info['sha256'] == hash), None)
    if(file_info == None):
        return HttpResponse('获取报告时发生错误:文件不存在')
    report = Report(file_info['path'])
    report.get_general_info_from_file_path(upload_time=file_info['time'])

    return render(request, 'report.html', {'info' : report.construct_report(),
                                            'hash' : hash,
                                            'real_file_name' : file_info['filename'].split('_')[-3] + '.' + file_info['filename'].split('_')[-1]})

class Report:
    '''
    用于构建报告
    '''
    def __init__(self, file_path):
        '''
        初始化，必须指定路径
        '''
        self.file_path = file_path
    
        self.info = {}
    
    def construct_report(self):
        '''
        构建报告
        '''
        return self.info
    def get_general_info_from_file_path(self,
                                        verdict=False,
                                        threats=[],
                                        extra_tags=[],
                                        upload_time=datetime.now()):
        '''
        从文件路径获取文件信息
        verdict : bool : 文件的检测结果
        threats : list : 威胁列表
        extra_tags : list : 额外的标签
        upload_time : datetime : 上传时间
        '''
        #取得文件名
        file_path = self.file_path
        if(os.path.exists(file_path) == False):
            raise FileNotFoundError("文件不存在")
        filename = os.path.basename(file_path)
        real_file_name=filename.split('_')[-3] + '.' + filename.split('_')[-1]
        extension = os.path.splitext(real_file_name)[-1]

        #处理threats参数
        if(len(threats) == 0):
            threats = '未检出威胁'
        else:
            for threat in threats:
                if(type(threat) != str):
                    raise ValueError('threats参数类型错误')
        
        #判断目标操作系统
        #应该使用pefile判断ARCH，作为TODO
        target_os = 'Windows 10'

        #按照拓展名猜测文件类型
        tags = extra_tags
        if(extension in ['.exe','.dll','sys','ocx', 'obj']):
            tags.append('portable_executable')
        elif (extension in ['.msi']):
            tags.append('windows_installer')
        elif (extension in ['.vbs','.js','.jse','.vbe']):
            tags.append('windows_script')
        elif (extension in ['.bat','.cmd']):
            tags.append('windows_batch')
        elif (extension in ['.ps1']):
            tags.append('powershell_script')
        elif (extension in ['.py','.pyc']):
            tags.append('python_script')



        #确定MIME类型
        import mimetypes
        # 猜测文件的MIME类型
        mime_type, _ = mimetypes.guess_type(file_path)
        if(mime_type == None):
            mime_type = 'file/unknown'
        #计算哈希值
        hash = {}
        with open(file_path, 'rb') as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
            f.seek(0)
            sha1 = hashlib.sha1(f.read()).hexdigest()
            f.seek(0)
            md5 = hashlib.md5(f.read()).hexdigest()
            f.seek(0)
            crc32 = compute_crc32(file_path)
            crc64 = 'Not Supported'
            blake2sp = hashlib.blake2s(f.read()).hexdigest()
            f.seek(0)
            try:
                import xxhash
                hasher = xxhash.xxh64()
                with open(file_path, 'rb') as file:
                    buf = file.read(4096)
                    # otherwise hash the entire file
                    while len(buf) > 0:
                        hasher.update(buf)
                        buf = file.read(4096)
                # Get the hashed representation
                xxh64 = hasher.intdigest()
            except ImportError:
                xxh64 = 'Not Supported'
        hash = {
            'CRC32': crc32,
            'CRC64': crc64,
            'SHA256': sha256,
            'SHA1': sha1,
            'BLAKE2sp': blake2sp,
            'XXH64': xxh64
        }

        #计算文件大小
        size = os.path.getsize(file_path)
        def format_size(size):
            # 确定单位和符号
            units = ['B', 'KB', 'MB', 'GB', 'TB']
            # 将下标初始化为0
            index = 0
            # 循环直到大小小于1024或者达到最后一个单位
            while size >= 1024 and index < len(units) - 1:
                # 将大小除以1024
                size /= 1024
                # 增加索引
                index += 1
            # 以2位小数和相应单位格式化大小
            size_str = f"{size:.2f} {units[index]}"
            return size_str

        # 使用size参数调用format_size函数
        size_str = format_size(size)

        #构建general_info
        general_info = {
            'filename' : filename,
            'verdict' : verdict,
            'threats': threats,
            'analysis_Time' : datetime.now(),
            'tagret_os' : target_os,
            'tags': tags,
            'MIME' : 'application/x-dosexec',
            'hash' : hash,
            'size' : size_str,
            'time' : upload_time,
        }
        self.info['general_info'] = general_info
        return general_info

def return_example_report_info():
    '''
    返回一个示例报告
    '''
    info={
        'general_info' : {
            'filename' : 'example.exe',
            'verdict' : 'Normal Activity',
            'threats': 'No Threats Detected',
            'analysis_Time' : datetime.now(),
            'tagret_os' : 'Windows 10',
            'tags': [
                'portable_executable',
                'windows_x86_64'
            ],
            'MIME' : 'application/x-dosexec',
            'hash' : {
                'CRC32': '6B47A4D5',
                'CRC64': 'C348EB0CCC7A3317',
                'SHA256': '8bfd26a1b1013bd620153140f9d827b0f7da80da588a50e1fba8fd041810da13',
                'SHA1': 'ced5a7e9310fa29b5d3738e064ce4c412131717b',
                'BLAKE2sp': 'e77cdc4746a9aaf798b8e078b6335a0938007a8df22523c6e238537e03c06494',
                'XXH64': '5D8B887DABAEC80F'
            },
            'size' : 12773,
            'time' : datetime.now(),
            'content_type' : 'application/x-dosexec'
            },
        'qiling_info' : {
            'rootfs' : 'x8664_windows',
            'argv' : ['example.exe'],
            'log_file' : 'log_qiling.log',
            'verbose' : 4,
            'runtime': 1664,
            'result' : 'TERMINATED',
            'qiling_errors' :[{
                    'error_type': 'Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)',
                    'error_log' :  r'''
Traceback (most recent call last):
File "<stdin>", line 1, in <module>
File "C:\Users\Jerry\AppData\Local\Programs\Python\Python311\Lib\site-packages\qiling\core.py", line 595, in run
    self.os.run()
File "C:\Users\Jerry\AppData\Local\Programs\Python\Python311\Lib\site-packages\qiling\os\windows\windows.py", line 212, in run
    self.ql.emu_start(entry_point, exit_point, self.ql.timeout, self.ql.count)
File "C:\Users\Jerry\AppData\Local\Programs\Python\Python311\Lib\site-packages\qiling\core.py", line 769, in emu_start
    self.uc.emu_start(begin, end, timeout, count)
File "C:\Users\Jerry\AppData\Local\Programs\Python\Python311\Lib\site-packages\unicorn\unicorn.py", line 547, in emu_start
    raise UcError(status)
unicorn.unicorn.UcError: Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)
                    ''',
                    'fatal' : True
                 }
            ],
            },
        'behavior_activities':{
            'malicious':[
                {
                    'description': 'Application tries to access the internet',
                    'process_name' : 'stub.exe',
                    'process_id' : 1234,
                },
                {
                    'description': 'Unusual execution from Microsoft Office',
                    'process_name' : 'MSWORD.exe',
                    'process_id' : 5566,
                }
            ],
            'suspicous':[],
            'info' :[]
        },
        'malware_configuration':[],
        'static_info':
        {
            'TRiD':[
                {
                    'extension' : 'exe',
                    'description' : 'Win32 Executable (generic)',
                    'possibility' : '100%'
                }
            ],
            'EXIF':[
                {
                    'main_type': 'exe',
                    'entry_point' : '0x00400000',
                    'linker' : 'Microsoft Visual C++ 6.0',
                    'complier' : 'Microsoft Visual C++ 6.0',
                    'link_time' : '1998:12:12 12:12:12',
                }
            ]
        },
        'report' : {
            'malware_detect' : {
                'detected' : False,
                'family' : [],
                'recommend_name' : 'null',
                'overall_report' : 'Good',
            },
            'api_calls' : [
                'CreateFileA',
                'CreateFileW',
                'CreateProcessA',
                'MessaeBoxA',
                'OutputdebugStringA',
                'RegOpenKeyExA',
            ],
            'key_suspicious_api_called' : [
                {
                    'api' : 'WinExec',
                    'args' : [
                        'cmd.exe /c echo "Hello World!"',
                        '0'
                    ]
                },{
                    "api": "CreateFile",
                    "args": [
                        "example.txt",
                        "GENERIC_WRITE",
                        "0",
                        "NULL",
                        "CREATE_NEW",
                        "FILE_ATTRIBUTE_NORMAL",
                        "NULL"
                    ]
                },{
                    "api": "ReadFile",
                    "args": [
                        "example.txt",
                        "buffer",
                        "512",
                        "&bytesRead",
                        "NULL"
                    ]
                },{
                    "api": "DeleteFile",
                    "args": [
                        "example.txt"
                    ]
                },{
                    "api": "MoveFile",
                    "args": [
                        "example.txt",
                        "new_location\\example.txt"
                    ]
                }
            ],
            'IO_strings':[
                'example.txt',
                'hello world',
                'This program cannot be run in DOS mode.',
            ],
            'strings':[],
            'yara' : {
                'provider' : 'CapeV2',
                'hits' : 0,
                'rules' : [],
                'result' : 'ERROR',
                'error' : 'Yara not supported'
            },
            'logs': 'path/to/logfile.log'
        }
    }
    return info
#### 私有方法

def scan_media_folder():
    '''
    扫描media文件夹，并且对文件夹下所有文件都执行get_file_info操作，写入submitted_files
    '''
    import os
    media_folder = 'media'
    submitted_files = []

    for root, dirs, files in os.walk(media_folder):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                new_file_name, file_info = get_file_info(file_path)
                submitted_files.append(file_info)
            except ValueError as e:
                #忽略重复文件
                continue
    return submitted_files

def get_file_info(file):
    '''
    获取文件信息
    file : str : 文件路径
    file : django.core.files.uploadedfile.InMemoryUploadedFile : 文件对象
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
        original_file_name, file_extension = filename.split('.')[-2], filename.split('.')[-1]

        # 获取当前时间戳
        timestamp = str(int(time.time()))

        # 替换非a-zA-Z0-9字符为下划线，构建新文件名
        new_file_name = re.sub(r'[^a-zA-Z0-9]', '_', file_hash) + '_' + original_file_name + '_' + timestamp + '_'+ file_extension

        file_info = {
            'time' : datetime.now(),
            'filename' : os.path.basename(file),
            'size' : os.path.getsize(file),
            'sha256' : file_hash,
            'path' : file
        }
        return new_file_name,file_info
    
    elif(type(file) == django.core.files.uploadedfile.InMemoryUploadedFile):
        sha256 = hashlib.sha256()
        for chunk in file.chunks():
            sha256.update(chunk)
        file_hash = sha256.hexdigest()
        if file_hash in [info['sha256'] for info in submitted_files]:
            raise ValueError('存在相同哈希值的文件')
        original_file_name, file_extension = file.name.split('.')[-2], file.name.split('.')[-1] 

        timestamp = str(int(time.time()))
        # 替换非a-zA-Z0-9字符为下划线
        new_file_name = re.sub(r'[^a-zA-Z0-9]', '_', file_hash) + '_' + original_file_name + '_' + timestamp + '_'+ file_extension

        file_info = {
            'time' : datetime.now(),
            'filename' : file.name,
            'size' : file.size,
            'sha256' : file_hash,
            'path' : f'media\\{new_file_name}'
        }
        return new_file_name,file_info
    else:
        raise AssertionError('未知的参数表类型')

def compute_crc32(file_path):
    import zlib
    with open(file_path, 'rb') as file:
        data = file.read()
        crc = zlib.crc32(data)
        return hex(crc & 0xFFFFFFFF)[2:].upper()
