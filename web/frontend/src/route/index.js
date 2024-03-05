import { createRouter, createWebHistory } from "vue-router";
import ReportDisplay from "../components/ReportDisplay.vue";
import ConfigDisplay from "../components/ConfigDisplay.vue";
import SummaryDisplay from '../components/SummaryDisplay.vue';
import SubmitDisplay from "../components/SubmitDisplay.vue";

const routes = [
  { path: '/' , name: 'summary' , component: SummaryDisplay},
  { path: '/config' , name:'config', component : ConfigDisplay},
  { path: '/submit', name:'submit', component:SubmitDisplay},
  { path: '/settings',name:'settings',component:ConfigDisplay},

  { path: '/report/:hash', name: 'report', component: ReportDisplay }
]


const router = createRouter({
  history: createWebHistory(),
  routes,
});


export default router;
