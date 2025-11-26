import { useUserStore } from '@/stores/userStore';

// export const authGuard = (to, from, next) => {
//   const userStore = useUserStore();
//   userStore.initialize();
  
//   if (to.meta.requiresAuth && !userStore.isAuthenticated) {
//     next('/username');
//   } else {
//     next();
//   }
// };

const authGuard = async (to, from, next) => {
  const userStore = useUserStore();
  await userStore.initialize();
  if (to.name === 'dashboard' && (!userStore.isAuthenticated || !userStore.isAdmin)) {
    console.log('Not admin, redirecting to /username');
    next('/username');
  } else if (to.meta.requiresAuth && !userStore.isAuthenticated) {
    console.log('Not authenticated, redirecting to /username');
    next('/username');
  } else {
    next();
  }
};