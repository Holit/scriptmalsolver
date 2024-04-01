from .profile import QilingProfile
from ..utils import *
import os

class Analyzer:
    def __init__(self, file_path: str):
        self._profile = QilingProfile()

    @staticmethod
    def get_roofts_root_dir():
        runtime_folder = get_runtime_folder()
        roofs_folder = os.path.join(os.path.dirname(os.path.dirname(runtime_folder)),'rootfs','Windows')
        return roofs_folder
