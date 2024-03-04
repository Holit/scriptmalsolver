
import hashlib
from datetime import datetime
from django.http import JsonResponse
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

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

@csrf_exempt
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
    
def report_file(file):
    
    report = {
        'risk' : False,
        'type' : 'PE',
        'architecture' : 'ARM',
        'family' : ''
    }
    return report

@csrf_exempt
def type_scan(request):
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
    
@csrf_exempt
def analyze_file(request):
    status = 500
    return JsonResponse({'error': 'Not-Implemented!'})

@csrf_exempt
def hello_world(request):
    html = "<html><body>Hello World!</body></html>"
    return HttpResponse(html)

def test_qiling(request):
    argv = [r'E:\Projects\scriptmalsolver\rootfs\x8664_windows\bin\hello.exe']
    rootfs = r'E:\Projects\scriptmalsolver\rootfs\x8664_windows'
    #verbose = qiling.QL_VERBOSE.DEBUG
    ql = qiling.Qiling(argv=argv, rootfs=rootfs, log_file = "log_qiling.log", verbose = 4)
    #ql = qiling.Qiling(argv=argv, rootfs=rootfs)
    ql.run()
    return JsonResponse({'result' : 'OK'})