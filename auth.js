const Auth = {
  install: function (Vue, store, router) {
    Object.defineProperties(Vue.prototype, {
      $auth: {
        get: function () {
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

    this.Vue.axios.interceptors.request.use(function (request) {
      if (process.env.NODE_ENV === 'development') {
        console.log('Request Interceptor: ' + JSON.stringify(request))
      }
      request.withCredentials = true
      return request
    })

    Vue.axios.interceptors.response.use(function (response) {
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
    return new Promise(function (resolve, reject) {
      if (!Auth.isLoggedIn()) {
        Auth.Vue.axios.get('http://localhost:3000/auth/list?referrer=' + encodeURIComponent(referrer))
        .then(function (response) {
          resolve(response.data)
        })
        .catch(function (error) {
          reject(error)
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
    return new Promise(function (resolve, reject) {
      Auth.Vue.axios.get('http://localhost:3000/auth/token?state=' + encodeURIComponent(state) + '&code=' + encodeURIComponent(code))
      .then(function (response) {
        Auth.store.dispatch('login', JSON.stringify(response.data.user))
        resolve(response.data.referrer)
      })
      .catch(function (error) {
        reject(error)
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
    LOGIN: function (state, user) {
      state.user = user
    },
    LOGOUT: function (state) {
      state.user = null
    }
  },
  actions: {
    reload: function ({commit, state}) {
      var user = localStorage.getItem('user')
      if (user !== state.user) {
        commit('LOGIN', user)
      }
    },
    login: function ({commit}, user) {
      localStorage.setItem('user', user)
      commit('LOGIN', user)
    },
    logout: function ({commit}) {
      localStorage.removeItem('user')
      commit('LOGOUT')
    }
  },
  getters: {
    user: function (state, getters) {
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
