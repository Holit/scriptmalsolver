<template>
    <header>
    <h1>在线文件查杀</h1>
  </header>
  <div id="fake-app">
    <FileUploader @file-list-updated="updateProperties" />
    <InfoDisplay :fileProperties="fileProperties" />
  </div>
</template>

<script>
import FileUploader from './FileUploader.vue';
import InfoDisplay from './InfoDisplay.vue';

export default {
  name: 'AppAsComponent',
  components: {
    FileUploader,
    InfoDisplay
  },
  data() {
    return {
      fileProperties: []
    }
  },
  methods: {
    updateProperties(newProperties) {
      this.fileProperties = newProperties;
    }
  }
}
</script>


<style scoped>
header {
  background-color: #1f1fc4;
  color: white;
  padding: 10px 20px;
}

h1 {
  margin: 0;
}

.wrapper {
  max-width: 800px;
  margin: 0 auto;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

nav {
  display: flex;
}

nav a {
  color: white;
  text-decoration: none;
  padding: 5px 10px;
}

nav a:hover {
  background-color: #555;
}

nav a.active {
  background-color: #555;
}

.RouterView {
  margin-top: 20px;
}

footer {
  background-color: #333;
  color: white;
  text-align: center;
  padding: 10px;
  position: fixed;
  left: 0;
  bottom: 0;
  width: 100%;
}
</style>
