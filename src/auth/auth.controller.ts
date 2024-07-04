import 'dotenv/config';
import { Context } from 'hono';
import { createAuthUserService, userLoginService, emailByUserId } from './auth.service';
import bcrypt from 'bcrypt';
import { sign } from 'hono/jwt';
import { sendEmail } from "../mailer";

export const registerUser = async (c: Context) => {
    try {
        const user = await c.req.json();
        const pass = user.password;
        const hashedPassword = await bcrypt.hash(pass, 10);
        user.password = hashedPassword;
        const createdUser = await createAuthUserService(user);
        if (!createdUser) return c.text("User not created", 404);
        const email = await emailByUserId(user.user_id);
        if (!email) {
            return c.json({ error: 'Email not found for the given user ID' }, 404);
        }

        // Send the email
        try {
            await sendEmail(email, user.name);
        } catch (error) {
            console.error("Error sending welcome email:", error);
            return c.json({ error: "failed to send  email but user registered successfull" }, 500);
        }

        return c.json({ msg: createdUser }, 201);

    } catch (error: any) {
        console.error("Error during registration:", error);
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
                exp: Math.floor(Date.now() / 1000) + (60 * 1800)  // 30 hour  => SESSION EXPIRATION
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
