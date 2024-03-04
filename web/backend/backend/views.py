
import hashlib
from datetime import datetime
from django.http import JsonResponse
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

import sys
sys.path.append("E:\Projects\scriptmalsolver\qiling")
from qiling import * 

import json

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

    result = ""
    ql = Qiling(argv=argv, rootfs=rootfs, log_file=result)
    ql.run()
    return JsonResponse({'module_name':Qiling.__name__,
                         'result' : result})