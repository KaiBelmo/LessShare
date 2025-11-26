import { defineStore } from 'pinia';
import { ref, computed } from 'vue';
import { useRouter } from 'vue-router';

export const useUserStore = defineStore('user', () => {
  const router = useRouter();
  const user = ref(null);
  const token = ref(null);
  const error = ref(null);

  const username = computed(() => user.value?.username || null);
  const userId = computed(() => user.value?.id || null);
  const isAdmin = computed(() => user.value?.isAdmin || false);
  const isAuthenticated = computed(() => !!token.value);

  const initialize = async () => {
    try {
      const storedUser = localStorage.getItem('lessshare_user');
      const storedToken = localStorage.getItem('lessshare_token');
      if (storedUser && storedToken) {
        user.value = JSON.parse(storedUser);
        token.value = storedToken;
        console.log('Initialized userStore:', user.value.username, 'isAdmin:', user.value.isAdmin);
      } else {
        console.log('No stored user or token found');
      }
    } catch (err) {
      console.error('Failed to initialize userStore:', err);
      logout();
    }
  };

  const login = (userData, authToken) => {
    user.value = userData;
    token.value = authToken;
    localStorage.setItem('lessshare_user', JSON.stringify(userData));
    localStorage.setItem('lessshare_token', authToken);
    error.value = null;
    console.log('Logged in:', userData.username, 'isAdmin:', userData.isAdmin);
  };

  const logout = () => {
    user.value = null;
    token.value = null;
    localStorage.removeItem('lessshare_user');
    localStorage.removeItem('lessshare_token');
    error.value = null;
    router.push('/username');
  };

  const destroyAccount = async () => {
    try {
      const response = await fetch('/api/users/me', {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token.value}`,
          'Content-Type': 'application/json'
        }
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Account deletion failed');
      }

      logout();
      return { success: true };
    } catch (err) {
      console.error('Account deletion failed:', err);
      error.value = err.message;
      return { success: false, error: err.message };
    }
  };

  return {
    user,
    token,
    username,
    userId,
    isAdmin,
    isAuthenticated,
    error,
    initialize,
    login,
    logout,
    destroyAccount
  };
});