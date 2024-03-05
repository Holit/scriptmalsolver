<template>
  <div id="app">

    <header>
      <h1>在线文件查杀</h1>
    </header>
    
    <div class="navbar">

      <div class="navbar-inner">
            <div class="container" style="width:1170px;">
              <ul class="nav" style="float:left">
                <li>
                  <router-link to="/">概要</router-link> |
                </li>                  
                <li>
                  <router-link to="/details">提交</router-link> |
                </li>
              </ul>
              <ul class="nav" style="float:right">
                  <li>
                    <router-link to="/settings">配置</router-link>
                  </li>
              </ul>
            </div>
      </div>
    </div>

    <router-view></router-view>
  </div>
  <footer>
    <span>©Copyright&nbsp;2024 <a href="https://www.hrbeu.edu.cn">哈尔滨工程大学</a> & <a href="https://www.antiy.cn">安天科技</a> </span>
  </footer>
</template>

<script>

export default {
  name: 'App',

}
</script>

<style scoped>
.body{
  margin: 0 auto; /* 居中显示 */
  width: 1170px;
  background-color: #c7c1c1;
}
.navbar {
    background-color: #ffffff;
    overflow: hidden;
}

.navbar-inner {
    padding: 10px;
}

.navbar-inner .container {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.navbar-inner ul.nav {
    list-style: none;
    margin: 0;
    padding: 0;
}

.navbar-inner ul.nav li {
    display: inline;
    margin-right: 10px;
}

.navbar-inner ul.nav li:last-child {
    margin-right: 0;
}

.navbar-inner ul.nav li router-link {
    color: #fff;
    text-decoration: none;
}

.navbar-inner ul.nav li router-link:hover {
    color: #ccc;
}

footer {
		position: fixed;
		bottom: 0;
		width: 100%;
		height: 40px;
		line-height: 40px;
		text-align: center;
		margin: 0;
		/* margin-top: 100px; */
		background: #f5f5f5;
		
}
</style>
