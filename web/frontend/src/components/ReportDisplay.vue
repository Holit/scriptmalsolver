<template>
    <div>
        <p>{{ parma }}</p>
    </div>
    <div>
        <h2>报告详情</h2>
        <p>是否存在风险：{{ report.risk ? '是' : '否' }}</p>
        <p>文件类型：{{ report.type }}</p>
        <p>架构：{{ report.architecture }}</p>
        <p>家族：{{ report.family || '未知' }}</p>
    </div>
    <router-view/>
</template>
  
<script>

export default {
    data() {
        return {
            hash: null
        };
    },
    created() {
        // 在页面创建时获取路由参数中的哈希值
        this.hash = this.$route.params.hash;
    },
    props: {
        report: {
            type: Object,
            required: true
        }
    },
}
</script>
  
<style scoped>
/* 样式 */
</style>
  