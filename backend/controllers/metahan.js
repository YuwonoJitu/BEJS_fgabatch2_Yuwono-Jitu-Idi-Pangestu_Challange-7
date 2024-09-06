const { PrismaClient } = require('@prisma/client');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

const login = async (req, res) => {
  const { email, password } = req.body;

  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  const isValidPassword = await bcrypt.compare(password, user.password);

  if (!isValidPassword) {
    return res.status(401).json({ message: 'Invalid password' });
  }

  const token = jwt.sign({ userId: user.id }, process.env.SECRET_KEY, {
    expiresIn: '1h',
  });

  res.json({ token });
};

const register = async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = await prisma.user.create({
    data: {
      firstName,
      lastName,
      email,
      password: hashedPassword,
    },
  });

  res.json({ message: 'User created successfully' });
};

const logout = async (req, res) => {
  const token = req.headers['x-access-token'] || req.headers['authorization'];

  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  const user = await prisma.user.findUnique({ where: { token } });

  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  await prisma.user.update({ where: { id: user.id }, data: { token: null } });

  res.json({ message: 'Logged out successfully' });
};

const forgotPassword = async (req, res) => {
    const { email } = req.body;
  
    // Generate a random token for reset password
    const resetToken = crypto.randomBytes(20).toString('hex');
  
    // Save the reset token to the user
    const user = await prisma.user.update({
      where: { email },
      data: { resetToken, resetTokenExpiry: new Date(Date.now() + 3600000) }, // expires in 1 hour
    });
  
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
  
    const mailOptions = {
      from: 'example@gmail.com',
      to: email,
      subject: 'Reset Password',
      text: `Hello,
  
      You requested to reset your password. Please click the following link to reset your password:
  
      http://localhost:3000/reset-password/${resetToken}
  
      This link will expire in 1 hour.
  
      If you did not request to reset your password, please ignore this email.
  
      Best regards,
      The Team`,
    };
  
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        return res.status(500).json({ message: 'Error sending email' });
      }
  
      res.json({ message: 'Email sent successfully' });
    });
  };
  
  const resetPassword = async (req, res) => {
    const { newPassword, resetToken } = req.body;
  
    const user = await prisma.user.findUnique({
      where: { resetToken },
    });
  
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
  
    // Check if the reset token is still valid
    if (user.resetTokenExpiry < new Date()) {
      return res.status(401).json({ message: 'Reset token has expired' });
    }
  
    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
  
    // Update the user's password and reset token
    await prisma.user.update({
      where: { email: user.email },
      data: { password: hashedPassword, resetToken: null, resetTokenExpiry: null },
    });
  
    res.json({ message: 'Password reset successfully' });
  };
  


module.exports = { login, register, logout, forgotPassword, resetPassword };