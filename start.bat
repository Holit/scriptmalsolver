echo 启动测试环境...
cd web/backend
echo 启动Django后端
start "Django Backend Terminal" cmd /k  py manage.py runserver
cd ..
cd frontend
echo 启动vue前端
start "Vue Frontend Terminal" cmd /k  npm run dev