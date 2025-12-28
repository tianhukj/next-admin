import { encrypt } from '@/utils/auth';

export type User = {
  email: string;
  pwdHash: string;
  role: number;
};

// demo in-memory user (not for production)
const users: User[] = [
  { email: 'admin@example.com', pwdHash: encrypt('admin123'), role: 1 }
];

export function findUserByEmail(email: string) {
  return users.find(u => u.email === email);
}

export function addUser(email: string, plainPwd: string) {
  const pwdHash = encrypt(plainPwd);
  const user: User = { email, pwdHash, role: 1 };
  users.push(user);
  return user;
}
