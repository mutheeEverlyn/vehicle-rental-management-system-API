import { AuthOnUsersTable, tiAuthOnUsers, tsAuthOnUsers } from "../drizzle/schema";
import db from "../drizzle/db";
import { sql } from "drizzle-orm";

export const createAuthUserService = async (user: tiAuthOnUsers): Promise<string | null> => {
    await db.insert(AuthOnUsersTable).values(user)
    return "User created successfully";
}

export const userLoginService = async (user: tsAuthOnUsers) => {
    const { email, password } = user;
    return await db.query.AuthOnUsersTable.findFirst({
        columns: {
            email: true,
            role: true,
            password: true
            
        }, where: sql` ${AuthOnUsersTable.email} = ${email}`,
        with: {
            user: {
                columns: {
                    full_name: true,
                    contact_phone: true,
                    email: true,
                    created_at:true,
                    updated_at: true
                }
            }
        }
    })
}
export const emailByUserId = async (id: number): Promise<string | null> => {
    const result = await db.query.usersTable.findFirst({
      columns: {
        email: true,
      },
      where: (usersTable, { eq }) => eq(usersTable.user_id, id),
    });
  
    if (!result) {
      return null;
    }
  
    return result.email;
  };