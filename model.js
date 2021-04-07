const path = require('path');
const { Sequelize, DataTypes } = require('sequelize');

const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: path.join(process.cwd(), '/db/users.db')
});


const User = sequelize.define('User', {
    _id: {
        type: DataTypes.STRING,
        primaryKey: true
    },
    name: {
        type: DataTypes.STRING
    },
    username: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true
    },
    password: {
        type: DataTypes.STRING
    },
    status: {
        type: DataTypes.STRING
    },
    lastLogin: {
        type: DataTypes.DATE
    }
});

module.exports = User;