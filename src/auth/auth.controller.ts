import 'dotenv/config';
import { Context } from 'hono';
import { createAuthUserService, userLoginService } from './auth.service';
import bcrypt from 'bcrypt';
import { sign } from 'hono/jwt';
import nodemailer from 'nodemailer';
import ejs from 'ejs';
import path from 'path';

// Nodemailer transporter configuration
const transporter = nodemailer.createTransport({
    service: 'gmail', 
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

export const registerUser = async (c: Context) => {
    try {
        const user = await c.req.json();
        const pass = user.password;
        const hashedPassword = await bcrypt.hash(pass, 10);
        user.password = hashedPassword;
        const createdUser = await createAuthUserService(user);
        if (!createdUser) return c.text("User not created", 404);

        // Render the EJS template to HTML
        ejs.renderFile(path.join(__dirname, 'src', 'registrationEmail.ejs'), { name: user.name }, (err, html) => {
            if (err) {
                return c.json({ error: 'Error in rendering email template' }, 500);
            }

            // Setup email options
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: user.email,
                subject: 'Welcome to Our Service',
                html: html
            };

            // Send email
            transporter.sendMail(mailOptions, (error, info) => {
                if (error) {
                    return c.json({ error: 'Error in sending email' }, 500);
                }
            });
        });

        return c.json({ msg: createdUser }, 201);

    } catch (error: any) {
        return c.json({ error: error?.message }, 400);
    }
};

export const loginUser = async (c: Context) => {
    try {
        const user = await c.req.json();
        const userExist = await userLoginService(user);
        if (userExist === null) return c.json({ error: 'User not found' }, 404);  // not found         
        const userMatch = await bcrypt.compare(user.password, userExist?.password as string);
        if (!userMatch) {
            return c.json({ error: 'Invalid details' }, 401);  // unauthorized
        } else {
            const payload = {
                sub: userExist?.email,
                role: userExist?.role,
                exp: Math.floor(Date.now() / 1000) + (60 * 1800)  // 3 hour  => SESSION EXPIRATION
            };
            const secret = process.env.JWT_SECRET as string;  // secret key
            const token = await sign(payload, secret);   // create a JWT token
            const user = userExist?.user;
            const role = userExist?.role;
            return c.json({ token, user: { role, ...user } }, 200);  // return token and user details
        }
    } catch (error: any) {
        return c.json({ error: error?.message }, 400);
    }
};
