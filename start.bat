echo �������Ի���...
cd web/backend
echo ����Django���
start "Django Backend Terminal" cmd /k  py manage.py runserver
cd ..
cd frontend
echo ����vueǰ��
start "Vue Frontend Terminal" cmd /k  npm run dev