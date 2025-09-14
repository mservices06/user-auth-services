import nodemailer from 'nodemailer';
import Mailgen from 'mailgen';

/**
 * Email Service
 * Handles all email-related operations using Nodemailer and Mailgen
 */
class EmailService {
  constructor() {
    // Create nodemailer transport using Mailtrap credentials
    this.transporter = nodemailer.createTransport({
      host: process.env.MAILTRAP_HOST,
      port: process.env.MAILTRAP_PORT,
      auth: {
        user: process.env.MAILTRAP_USER,
        pass: process.env.MAILTRAP_PASS
      }
    });

    // Configure Mailgen instance
    this.mailGenerator = new Mailgen({
      theme: 'default',
      product: {
        name: 'User Service',
        link: process.env.FRONTEND_URL || 'http://localhost:3000',
        logo: 'https://via.placeholder.com/150x50'
      }
    });
  }

  /**
   * Generate email verification email content
   * @param {Object} user - User object
   * @param {string} token - Verification token
   * @returns {Object} Email content with HTML and text versions
   */
  generateVerificationEmail(user, token) {
    const verificationUrl = `${process.env.API_URL || 'http://localhost:4000'}/api/auth/verify-email?token=${token}`;
    
    // Define email content
    const email = {
      body: {
        name: user.name,
        intro: 'Welcome to our service! We\'re excited to have you on board.',
        action: {
          instructions: 'To verify your email address, please click the button below:',
          button: {
            color: '#22BC66',
            text: 'Verify Your Email',
            link: verificationUrl
          }
        },
        outro: 'If you did not create an account, no further action is required.'
      }
    };

    // Generate HTML and plaintext versions
    return {
      html: this.mailGenerator.generate(email),
      text: this.mailGenerator.generatePlaintext(email)
    };
  }

  /**
   * Generate password reset email content
   * @param {Object} user - User object
   * @param {string} token - Reset token
   * @returns {Object} Email content with HTML and text versions
   */
  generateResetPasswordEmail(user, token) {
    const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password?token=${token}`;
    
    // Define email content
    const email = {
      body: {
        name: user.name,
        intro: 'You have requested to reset your password.',
        action: {
          instructions: 'To reset your password, please click the button below:',
          button: {
            color: '#DC4D2F',
            text: 'Reset Your Password',
            link: resetUrl
          }
        },
        outro: 'If you did not request a password reset, no further action is required.'
      }
    };

    // Generate HTML and plaintext versions
    return {
      html: this.mailGenerator.generate(email),
      text: this.mailGenerator.generatePlaintext(email)
    };
  }

  /**
   * Send an email
   * @param {string} to - Recipient email
   * @param {string} subject - Email subject
   * @param {string} html - HTML content
   * @param {string} [text] - Plaintext content (optional)
   * @returns {Promise} Nodemailer send result
   */
  async sendMail(to, subject, html, text) {
    const mailOptions = {
      from: process.env.EMAIL_FROM || 'noreply@userservice.com',
      to,
      subject,
      html,
      text
    };

    return this.transporter.sendMail(mailOptions);
  }
}

// Create a singleton instance
const emailService = new EmailService();

export default emailService; 