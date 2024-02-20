
import hashlib
from datetime import datetime
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def upload_file(request):
    if request.method == 'POST' and request.FILES:
        uploaded_files = request.FILES.getlist('files')
        hashes = []
        fileProperties = []
        for file in uploaded_files:
            # 读取文件内容并计算哈希值
            info = {
                'name' : file.name,
                'size' : file.size,
                'time' : datetime.now(),
                'content_type' : file.content_type,
                'hash' : hashlib.sha256(file.read()).hexdigest()
            }
            fileProperties.append(info)
        return JsonResponse({'fileProperties': fileProperties})
    else:
        return JsonResponse({'error': '请上传文件'}, status=400)
