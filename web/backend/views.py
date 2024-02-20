
import hashlib
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def upload_file(request):
    if request.method == 'POST' and request.FILES:
        uploaded_files = request.FILES.getlist('files')
        hashes = []
        
        for file in uploaded_files:
            # 读取文件内容并计算哈希值
            file_content = file.read()
            file_hash = hashlib.sha256(file_content).hexdigest()
            hashes.append(file_hash)
        
        return JsonResponse({'hashes': hashes})
    else:
        return JsonResponse({'error': '请上传文件'}, status=400)
