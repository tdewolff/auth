import Vue from 'vue'
import jwtDecode from 'jwt-decode'
import router from './router'
import config from '../../config'

const Auth = {
  install (Vue, store) {
    Object.defineProperties(Vue.prototype, {
      $auth: {
        get () {
          return Auth
        }
      }
    })

    store.registerModule('auth', AuthStore)
    this.store = store

    // Reload Vuex state if localStorage is changed in another tab
    window.addEventListener('storage', () => {
      Auth.store.dispatch('reload')
    }, false)

    Vue.axios.interceptors.request.use(request => {
      if (process.env.NODE_ENV === 'development') {
        console.log('Request: ' + JSON.stringify(request))
      }
      if (Auth.isLoggedIn()) {
        request.headers.common['authorization'] = Auth.store.getters.jwt
      }
      return request
    })

    Vue.axios.interceptors.response.use(response => {
      if (process.env.NODE_ENV === 'development') {
        console.log('Response: ' + JSON.stringify(response))
      }
      if (response.headers['set-authorization']) {
        Auth.store.dispatch('login', response.headers['set-authorization'])
      }
      return response
    }, error => {
      if (error.response && error.response.status === 401) {
        Auth.store.dispatch('logout')
        router.push('/?referrer=' + encodeURIComponent(router.history.current.path))
      }
      return Promise.reject(error)
    })

    if (Auth.isLoggedIn() && (Auth.getUser()['exp'] * 1000 < new Date().getTime() || Auth.getUser()['nbf'] * 1000 > new Date().getTime())) {
      Auth.store.dispatch('logout')
    }
  },
  getAuthURLs: function (referrer) {
    return new Promise((resolve, reject) => {
      if (!Auth.isLoggedIn()) {
        Vue.axios.get(config.URL + '/auth/list?referrer=' + encodeURIComponent(referrer), {withCredentials: true})
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
    return !!Auth.store.getters.jwt
  },
  getUser: function () {
    if (this.isLoggedIn()) {
      return Auth.store.getters.user
    }
  },
  login: function (state, code) {
    const timezone = new Intl.DateTimeFormat().resolvedOptions().timeZone
    return new Promise((resolve, reject) => {
      Vue.axios.get(config.URL + '/auth/token?state=' + encodeURIComponent(state) + '&code=' + encodeURIComponent(code) + '&timezone=' + encodeURIComponent(timezone), {withCredentials: true})
      .then(response => {
        resolve(response.data)
      })
      .catch(e => {
        reject(e)
      })
    })
  },
  logout: function () {
    Auth.store.dispatch('logout')
  }
}

const AuthStore = {
  state: {
    jwt: localStorage.getItem('jwt')
  },
  mutations: {
    LOGIN: (state, jwt) => {
      state.jwt = jwt
    },
    LOGOUT: (state) => {
      state.jwt = null
    }
  },
  actions: {
    reload ({commit, state}) {
      var jwt = localStorage.getItem('jwt')
      if (jwt !== state.jwt) {
        commit('LOGIN', jwt)
      }
    },
    login ({commit}, jwt) {
      localStorage.setItem('jwt', jwt)
      commit('LOGIN', jwt)
    },
    logout ({commit}) {
      localStorage.removeItem('jwt')
      commit('LOGOUT')
    }
  },
  getters: {
    jwt: (state, getters) => {
      if (state.jwt) {
        try {
          return state.jwt
        } catch (e) {
          return null
        }
      }
      return null
    },
    user: (state, getters) => {
      if (getters.jwt) {
        return jwtDecode(getters.jwt)
      }
      return null
    }
  }
}

export default Auth
