<template>
  Guess what, this page is not done yet!
</template>

<script>
export default {
  name: 'SummaryDisplay',
  components: {

  },
  data() {
    return {
    }
  },
  methods: {
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
./Summary.vue./Submit.vue