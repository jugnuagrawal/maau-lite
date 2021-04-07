const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const isEmail = require('validator/lib/isEmail');
const User = require('./model');

const SECRET = process.env.SECRET || 'covid-19';
const TOKEN_TTL = process.env.TOKEN_TTL || 7200;

async function login(req, res) {
    const payload = req.body;
    if (!payload.username || !payload.username.trim() || !payload.password || !payload.password.trim() || !isEmail(payload.username)) {
        return res.status(400).json({ message: 'Invalid Username/Password' });
    }
    const user = await User.findOne({ where: { username: payload.username } });
    if (!user) {
        return res.status(400).json({ message: 'Invalid Username/Password' });
    }
    if (!bcrypt.compareSync(payload.password, user.password)) {
        return res.status(400).json({ message: 'Invalid Username/Password' });
    }
    const data = user.toJSON();
    delete data.password;
    delete data._id;
    const token = jwt.sign(data, SECRET, { expiresIn: TOKEN_TTL });
    data.token = token;
    res.status(200).json(data);
}


async function register(req, res) {
    const payload = req.body;
    if (!payload.name || !payload.name.trim()) {
        return res.status(400).json({ message: 'Name is required' });
    }
    if (!payload.username || !payload.username.trim()) {
        return res.status(400).json({ message: 'Username is required' });
    }
    if (!payload.password || !payload.password.trim()) {
        return res.status(400).json({ message: 'Password is required' });
    }
    if (!isEmail(payload.username)) {
        return res.status(400).json({ message: 'Username should be your email' });
    }
    const user = await User.findOne({ where: { username: payload.username } });
    if (user) {
        return res.status(400).json({ message: 'User with same username exists' });
    }
    payload.password = bcrypt.hashSync(payload.password, 10);
    const status = await User.create(payload);
    res.status(200).json({ message: 'User Created Successfully' });
}


async function validate(req, res) {
    let token = req.header('Authorization');
    if (!token) {
        token = req.cookies['maau-token'];
    }
    if (!token) {
        return res.status(401).json({ message: 'Invalid Token' });
    }
    const data = jwt.decode(token, SECRET);
    if (!data) {
        return res.status(401).json({ message: 'Invalid Token' });
    }
    const user = await User.findOne({ where: { username: data.username } });
    if (!user) {
        return res.status(401).json({ message: 'Invalid Token' });
    }
    res.status(200).json({ message: 'Valid Token' });
}


async function refresh(req, res) {
    let token = req.header('Authorization');
    if (!token) {
        token = req.cookies['maau-token'];
    }
    if (!token) {
        return res.status(401).json({ message: 'Invalid Token' });
    }
    const data = jwt.decode(token, SECRET);
    if (!data) {
        return res.status(401).json({ message: 'Invalid Token' });
    }
    const user = await User.findOne({ where: { username: data.username } });
    if (!user) {
        return res.status(401).json({ message: 'Invalid Token' });
    }
    delete data.password;
    delete data._id;
    const token = jwt.sign(data, SECRET, { expiresIn: TOKEN_TTL });
    data.token = token;
    res.status(200).json(data);
}

async function changePassword(req, res) {
    const payload = req.body;
    let token = req.header('Authorization');
    if (!token) {
        token = req.cookies['maau-token'];
    }
    if (!token) {
        return res.status(401).json({ message: 'Invalid Token' });
    }
    const data = jwt.decode(token, SECRET);
    if (!data) {
        return res.status(401).json({ message: 'Invalid Token' });
    }
    if (!payload.oldPassword || !payload.oldPassword.trim()) {
        return res.status(400).json({ message: 'Old Password is required' });
    }
    if (!payload.cpassword || !payload.cpassword.trim()) {
        return res.status(400).json({ message: 'Confirm Password is required' });
    }
    if (!payload.password || !payload.password.trim()) {
        return res.status(400).json({ message: 'Password is required' });
    }
    if (payload.password !== payload.cpassword) {
        return res.status(400).json({ message: 'Passwords do not match' });
    }

    const user = await User.findOne({ where: { username: data.username } });
    if (!user) {
        return res.status(401).json({ message: 'Invalid Token' });
    }
    if (!bcrypt.compareSync(payload.oldPassword, user.password)) {
        return res.status(400).json({ message: 'Invalid Old Password' });
    }
    user.set('password', bcrypt.hashSync(payload.password, 10));
    const status = await user.save();
    res.status(200).json({ message: 'Password Changed Successfully' });
}