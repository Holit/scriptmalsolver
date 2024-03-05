<template>
  <div>
    <div class="file-upload-container">
      <div class="file-upload"
        @dragover.prevent
        @drop="handleDrop">
        <div class="decoration"></div>
        <label for="fileInput" class="file-input-label">
          <span>点击这里选择文件</span>
          <input type="file" id="fileInput" multiple @change="uploadFiles" />
        </label>
        <div class="decoration"></div>
      </div>
    </div>
  </div>
</template>
  
<script>
import axios from 'axios';

export default {
  name: 'SubmitDisplay',
  data() {
    return {
      fileProperties: []
    }
  },
  methods: {
    handleDrop(event) {
      event.preventDefault();
      const files = event.dataTransfer.files;
      this.uploadFiles(files);
    },
    async uploadFiles(event) {
      const files = event.target.files;
      const formData = new FormData();

      for (let i = 0; i < files.length; i++) {
        formData.append('files', files[i]);
      }

      try {
        const response = await axios.post('/api/upload/', formData, {
          headers: {
            'Content-Type': 'multipart/form-data'
          }
        });
        this.fileProperties = response.data.fileProperties;
        this.$emit('file-list-updated', this.fileProperties);
      } catch (error) {
        if(error.response != undefined)
        {
          if(error.response.status != 400)
          {
            console.error('上传文件时发生错误:', error);
          }
        }
        else
        {
          console.error('上传文件时发生错误: 未知错误')
        }
      }
    }
  }
}
</script>
  
<style>
.file-upload-container {
  max-width: 400px;
  /* 设置最大宽度 */
  margin: 0 auto;
  /* 居中显示 */
}

.file-upload {
  margin: 20px;
  padding: 20px;
  border: 2px dashed #ccc;
  border-radius: 5px;
  background-color: #f9f9f9;
}

.decoration {
  height: 10px;
}

.file-input-label {
  display: block;
  text-align: center;
  font-size: 18px;
  color: #333;
  cursor: pointer;
}

.file-input-label span {
  display: block;
  margin-bottom: 10px;
}

input[type="file"] {
  display: none;
}
</style>
  