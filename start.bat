echo �������Ի���...
cd web/backend
echo ����Django���
start "Django Backend Terminal" cmd /c  py manage.py runserver
cd ..
cd frontend
echo ����vueǰ��
start "Vue Frontend Terminal" cmd /c  npm run dev