echo 启动测试环境...
cd web
echo 启动Django后端
start "Django Backend Terminal" cmd /c  py manage.py runserver
cd frontend
echo 启动vue前端
start "Vue Frontend Terminal" cmd /c  npm run dev