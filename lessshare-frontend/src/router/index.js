import { createRouter, createWebHistory } from 'vue-router'
import HomeView from '../views/HomeView.vue'
import UsernameView from '../views/UsernameView.vue'
import RoomsView from '../views/RoomsView.vue'
import HowItWorksView from '../views/HowItWorksView.vue'
import RoomView from '../views/RoomView.vue'
import DashboardView from '../views/DashboardView.vue'
import AdminLoginView from '../views/AdminLoginView.vue' // 👈 Add AdminLoginView
import { useUserStore } from '../stores/userStore'

const authGuard = async (to, from, next) => {
  const userStore = useUserStore();
  await userStore.initialize();
  if (to.name === 'dashboard' && (!userStore.isAuthenticated || !userStore.isAdmin)) {
    console.log('Not admin, redirecting to /admin-login');
    next({ name: 'admin-login', query: { redirect: to.fullPath } });
  } else if (to.meta.requiresAuth && !userStore.isAuthenticated) {
    console.log('Not authenticated, redirecting to /username');
    next('/username');
  } else {
    next();
  }
};

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'home',
      component: HomeView
    },
    {
      path: '/username',
      name: 'username',
      component: UsernameView
    },
    {
      path: '/admin-login', // 👈 Add admin-login route
      name: 'admin-login',
      component: AdminLoginView
    },
    {
      path: '/dashboard',
      name: 'dashboard',
      component: DashboardView,
      meta: { requiresAuth: true }
    },
    {
      path: '/rooms',
      name: 'rooms',
      component: RoomsView
    },
    {
      path: '/how-it-works',
      name: 'how-it-works',
      component: HowItWorksView
    },
    {
      path: '/room/:id',
      name: 'room',
      component: RoomView
    }
  ]
})

router.beforeEach(authGuard)

export default router