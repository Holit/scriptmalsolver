document.addEventListener('DOMContentLoaded', function() {
  const pages = ['staticinfo-page', 'os-page', 'runtime-page', 'userenv-page', 'hardware-page', 'os-detail-page', 'qiling-page', 'enhance-page'];
  pages.forEach(function(Item) {

    const navItem = document.getElementById('nav-' + Item);
    const page = document.getElementById(Item);
    console.info(navItem, page);
    navItem.addEventListener('click', function(event) {
      event.preventDefault();

      // 设置当前激活的导航项
      pages.forEach(function(id) {
        nav_bar = 'nav-' + id
        document.getElementById(nav_bar).classList.remove('active');
      });
      navItem.classList.add('active');

      // 设置当前页面显示，其他页面隐藏
      pages.forEach(function(id) {
        document.getElementById(id).classList.add('hidden');
      });
      page.classList.remove('hidden');
    });
  });
});
