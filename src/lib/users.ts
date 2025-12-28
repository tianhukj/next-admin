import bcrypt from 'bcryptjs';

export type User = {
  email: string;
  pwdHash: string;
  role: number;
};

// 示例内存用户（演示用）
// 密码: admin123
const users: User[] = [
  {
    email: 'admin@example.com',
    pwdHash: bcrypt.hashSync('admin123', 10),
    role: 1
  }
];

export function findUserByEmail(email: string) {
  return users.find(u => u.email === email);
}

export function addUser(email: string, plainPwd: string) {
  const pwdHash = bcrypt.hashSync(plainPwd, 10);
  const user: User = { email, pwdHash, role: 1 };
  users.push(user);
  return user;
}
