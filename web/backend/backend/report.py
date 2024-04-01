import datetime
import hashlib
import os
from .utils import *

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
    def get_general_info(self,
                        verdict=False,
                        threats=[],
                        extra_tags=[],
                        upload_time=datetime.datetime.now()):
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
        real_file_name=filename.split('_')[0] + '.' + filename.split('_')[-1]
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
            'analysis_Time' : datetime.datetime.now(),
            'tagret_os' : target_os,
            'tags': tags,
            'MIME' : 'application/x-dosexec',
            'hash' : hash,
            'size' : size_str,
            'time' : upload_time,
        }
        self.info['general_info'] = general_info
        return general_info
    
    @staticmethod
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
