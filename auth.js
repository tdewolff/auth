const Auth = {
  install (Vue, store, router) {
    Object.defineProperties(Vue.prototype, {
      $auth: {
        get () {
          return Auth
        }
      }
    })

    store.registerModule('auth', AuthStore)
    this.store = store
    this.router = router
    this.Vue = Vue

    // Reload Vuex state if localStorage is changed in another tab
    window.addEventListener('storage', function () {
      Auth.store.dispatch('reload')
    }, false)

    this.Vue.axios.interceptors.request.use((request) => {
      if (process.env.NODE_ENV === 'development') {
        console.log('Request Interceptor: ' + JSON.stringify(request))
      }
      request.withCredentials = true
      return request
    })

    Vue.axios.interceptors.response.use((response) => {
      if (process.env.NODE_ENV === 'development') {
        console.log('Response Interceptor: ' + JSON.stringify(response))
      }
      return response
    }, function (error) {
      if (error.response && error.response.status === 401) {
        Auth.store.dispatch('logout')
        router.push('/auth?referrer=' + encodeURIComponent(router.history.current.path))
      }
      return Promise.reject(error)
    })
  },
  getAuthURLs: function (referrer) {
    return new Promise((resolve, reject) => {
      if (!Auth.isLoggedIn()) {
        Auth.Vue.axios.get('http://localhost:3000/auth/list?referrer=' + encodeURIComponent(referrer))
        .then(response => {
          resolve(response.data)
        })
        .catch(e => {
          reject(e)
        })
      } else {
        reject('already logged in')
      }
    })
  },
  isLoggedIn: function () {
    return !!Auth.store.getters.user
  },
  getUser: function () {
    if (this.isLoggedIn()) {
      return Auth.store.getters.user
    }
  },
  login: function (state, code) {
    return new Promise((resolve, reject) => {
      Auth.Vue.axios.get('http://localhost:3000/auth/token?state=' + encodeURIComponent(state) + '&code=' + encodeURIComponent(code))
      .then(response => {
        Auth.store.dispatch('login', JSON.stringify(response.data.user))
        resolve(response.data.referrer)
      })
      .catch(e => {
        reject(e)
      })
    })
  },
  logout: function () {
    Auth.store.dispatch('logout')
    Auth.Vue.axios.get('http://localhost:3000/auth/logout')
  }
}

const AuthStore = {
  state: {
    user: localStorage.getItem('user')
  },
  mutations: {
    LOGIN: (state, user) => {
      state.user = user
    },
    LOGOUT: (state) => {
      state.user = null
    }
  },
  actions: {
    reload ({commit, state}) {
      var user = localStorage.getItem('user')
      if (user !== state.user) {
        commit('LOGIN', user)
      }
    },
    login ({commit}, user) {
      localStorage.setItem('user', user)
      commit('LOGIN', user)
    },
    logout ({commit}) {
      localStorage.removeItem('user')
      commit('LOGOUT')
    }
  },
  getters: {
    user: (state, getters) => {
      if (state.user) {
        try {
          return JSON.parse(state.user)
        } catch (e) {
          return null
        }
      }
      return null
    }
  }
}

export default Auth
