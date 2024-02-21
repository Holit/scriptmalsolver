import { createRouter, createWebHistory } from "vue-router";
import ReportDisplay from "../components/ReportDisplay.vue";
import TestDisplay from "../components/TestDisplay.vue";
import AppAsComponent from '../components/AppAsComponent.vue'
//import { readonly } from "vue";

const routes = [
  { path: '/' , name: 'app' , component: AppAsComponent},
  { path: '/report/:hash', name: 'report', component: ReportDisplay },
  { path: '/helloworld' , name:'helloworld', component : TestDisplay}
]


const router = createRouter({
  history: createWebHistory(),
  routes,
});


export default router;
