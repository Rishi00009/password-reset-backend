const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'rishirishim0@gmail.com', 
    pass: 'Rishi1',        
  },
});
