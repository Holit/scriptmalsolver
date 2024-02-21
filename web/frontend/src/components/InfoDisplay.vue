<template>
  <div>
    <h2>上传文件信息：</h2>
    <div class="table-container">
      <table class="table">
        <thead>
          <tr>
            <th>ID</th>
            <th>时间</th>
            <th>文件名</th>
            <th>大小</th>
            <th>哈希值</th>
            <th>风险</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(file, index) in fileProperties" :key="index">
            <td>{{ index }}</td>
            <td>{{ file.time }}</td>
            <td>{{ file.name }}</td>
            <td>{{ file.size }}</td>
            <td><a :href="`/report/${file.hash}`" target="_blank">{{ file.hash }}</a>
</td>
            <td>{{ file.report.risk == True ? '是' : '否' }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
  
<script>
export default {
  data()
  {
    return []
  },
  props: {
    fileProperties: {
      type: Array,
      required: true
    }
  },
  methods:{
  }
}
</script>
  
<style>
/* 样式 */
.table-container {
  overflow-x: auto;
  /* 添加水平滚动条 */
}

.table {
  width: 100%;
  /* 表格宽度设置为100% */
  border-collapse: collapse;
  /* 合并单元格边框 */
}

.table th,
.table td {
  border: 1px solid #ddd;
  /* 单元格边框 */
  padding: 8px;
  /* 单元格内边距 */
  text-align: left;
  /* 文字左对齐 */
}

.table th {
  background-color: #f2f2f2;
  /* 表头背景色 */
}</style>
