const { PrismaClient } = require("@prisma/client");
const bycrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
// const User = require("../models/User");
const { transporter } = require("../config/mailer");

const prisma = new PrismaClient();

// Auth Function
async function login(req, res, next) {

	// Get User Agent (Client Information)
	const user_agent = req.headers['user-agent'];

	// Get Data User From Request
	const user_payload = {
		email: req.body.email,
		password: req.body.password
	};

	// Get User From Database
	const user = await prisma.user.findUnique({
		where: {
			email: user_payload.email
		}
	});

	// Check if User Not Found
	if (!user) {
		return res.status(400).json({ message: 'User Not Found' });
	}

	// Check Password
	const passwordMatch = bycrypt.compareSync(user_payload.password, user.password);

	// Check if Password Not Match
	if (!passwordMatch) {
		return res.status(400).json({ message: 'Username or Password Not Match' });
	}

	if (user_agent === user.user_agent) {
		// Generate JWT Token
		const token = jwt.sign({ email: user.email, id_user: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

		// Return Response
		return res.status(200).json({ message: 'Login Success', token: token });
	} else {
		// Generate OTP and Send to User Email
		// const otp = Math.floor(1000 + Math.random() * 9000);
		const otp = crypto.randomInt(10000, 100000);

		// Update User to column OTP
		await prisma.user.update({
			where: {
				email: user.email
			},
			data: {
				otp: otp.toString(),
				//user_agent: user_agent
			}
		});

		// Send OTP to User Email
		transporter.sendMail({
			from: process.env.EMAIL,
			to: user.email,
			subject: 'Verfikasi Kode OTP',
			text: `Kode OTP Anda ${otp}`
		});

		// Return Response
		return res.status(200).json({ 
			message: 'Silahkan Cek Email Anda',
			is_need_otp: true
		 });
	}
}

async function register(req, res, next) {

	// Get Data User From Request
	const user_payload = {
		email: req.body.email,
		password: await bycrypt.hash(req.body.password, 10),
		name: req.body.name
	};

	// Find User From Database
	const user = await prisma.user.findUnique({
		where: {
			email: user_payload.email
		}
	});

	// Check if User Already Exist
	if (user) {
		return res.status(400).json({ message: 'User Already Exist' });
	}

	// Save User to Database
	await prisma.user.create({
		data: user_payload
	});

	// Return Response
	return res.status(200).json({ message: 'Register Success' });
}

async function verifyOTP(req, res, next) {
	// Get Data User From Request
	const user_payload = {
		email: req.body.email,
		otp: req.body.otp
	};

	// Find User From Database
	const user = await prisma.user.findUnique({
		where: {
			email: user_payload.email
		}
	});

	// Check if User Not Found
	if (!user) {
		return res.status(400).json({ message: 'User Not Found' });
	}

	// Check if OTP Not Match
	if (user.otp !== user_payload.otp) {
		return res.status(400).json({ message: 'OTP Not Match' });
	}

	// Generate Token
	const token = await jwt.sign({ email: user.email, id_user: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });

	// Update User to column OTP
	await prisma.user.update({
		where: {
			email: user.email
		},
		data: {
			otp: null
		}
	});

	// Return Response
	return res.status(200).json({ message: 'OTP Verified', token: token });
}

async function forgotPassword(req, res, next) {
	// Get Data User From Request
	const user_payload = {
	  email: req.body.email
	};
  
	// Find User From Database
	const user = await prisma.user.findUnique({
	  where: {
		email: user_payload.email
	  }
	});
  
	// Check if User Not Found
	if (!user) {
	  return res.status(400).json({ message: 'User Not Found' });
	}
  
	// Generate Token untuk reset password
	const otp = crypto.randomInt(10000, 100000);
  
	// Update User to column resetToken
	await prisma.user.update({
		where: {
			email: user.email
		},
		data: {
			otp: otp.toString(),
	  }
	});
  
	// Send Email dengan link reset password
	transporter.sendMail({
	  from: process.env.EMAIL,
	  to: user.email,
	  subject: 'Verfikasi Kode OTP Reset Password',
	  text: `Kode OTP berikut untuk reset password Anda ${otp}`
	});
  
	// Return Response
	return res.status(200).json({ message: 'Silahkan cek email Anda' });
  }
  
  async function resetPassword(req, res, next) {
	// Get Data User From Request
	const user_payload = {
	  otp: req.params.otp,
	  password: req.body.password
	};
  
	// Find User From Database
	const user = await prisma.user.findFirst({
	  where: {
		otp: user_payload.otp
	  }
	});
  
	// Check if User Not Found
	if (!user) {
	  return res.status(400).json({ message: 'User Not Found' });
	}
  
	// Update User password
	await prisma.user.update({
	  where: {
		email: user.email
	  },
	  data: {
		password: await bycrypt.hash(user_payload.password, 10),
		otp: null
	  }
	});
  
	// Return Response
	return res.status(200).json({ message: 'Password berhasil direset' });
  }

module.exports = {
	login,
	register,
	verifyOTP,
	forgotPassword,
	resetPassword
};