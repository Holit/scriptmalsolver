import { createApp } from 'vue'
import App from './App.vue'
import router from './route'
import axios from 'axios'

axios.defaults.timeout = 5000
axios.defaults.baseURL = "http://localhost:8000"
createApp(App).use(router).mount('#app')
