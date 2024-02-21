<template>
    <div>
      <h1>File Hash: {{ file_hash }}</h1>
      <!--
        TODO:
        后端：收到文件后，放入队列，等待扫描，生成json报告并存储。
        前端：通知后端，读取json报告。
      -->
    </div>
  </template>
  
<script>

export default {
    created() {
        // 在页面创建时获取路由参数中的哈希值
        this.file_hash = this.$route.params.hash;
    },
    data() {
        return {
        file_hash: '' // 初始化 file_hash 属性
        };
    },
    props: {
        report: {
            type: Object,
            required: false
        }
    },
}
</script>
  
<style scoped>
/* 样式 */
</style>
  