# scriptmalsolver  

一个基于[qiling](https://github.com/qilingframework/qiling)的加载器识别沙箱。

## 目标

本项目希望基于qiling虚拟执行平台，对加载器家族恶意软件进行标记和辅助分析作用，期望完成如下目标：

* 对不同家族的加载器应用（yara）规则进行标记，方便分类
* 试图从加载器中dump出内部加密的载荷

## 运行本项目

本项目被设计为如下形式

```
-----------------------------
|     qiling(modified) 		|
|    Scan and Process   	|
-----------------------------
      logs|↑
          ↓|files
-----------------------------
|        Django          	|
|      (Backend)        	|
|							|
-----------------------------
    Report|↑
		  ↓|User Interactions
-----------------------------
|  		Django.template    	|
|    	 (Frontend)      	|	
|    	   Render          	|
-----------------------------
```

启动根目录下的start.bat即可启动网页实例。




-----------

为确保本项目的README简洁，在下方贴出父项目qiling的README链接。

[qilingframework/qiling: A True Instrumentable Binary Emulation Framework (github.com)](https://github.com/qilingframework/qiling)
