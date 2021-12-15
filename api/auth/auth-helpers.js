const jwt = require('jsonwebtoken')
const {JWT_SECRET} = require('../secrets/index')

function tokenBuilder(user) {
    const payload = {
        subject: user.user_id,
        username: user.username, 
        role_name: user.role_name
    }
    const options = {
        expiresIn: '1d'
    }
    const result = jwt.sign(payload, JWT_SECRET, options)
    console.log(result)

    return result
}

module.exports = {
    tokenBuilder,
}