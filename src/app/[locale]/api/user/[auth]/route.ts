import { NextResponse } from 'next/server';
import jsonwebtoken from 'jsonwebtoken';
import { cookies } from 'next/headers';
import { findUserByEmail, addUser } from '@/lib/users';
import { encrypt } from '@/utils/auth';

export async function POST(
  request: Request,
  { params: { auth } }: { params: { auth: string } }
) {
  const { email, pwd } = await request.json();
  const threeDays = 3 * 24 * 60 * 60 * 1000;
  const jwtSecret = process.env.JWT_SECRET;

  if (!jwtSecret) {
    return NextResponse.json({ msg: '服务端配置异常' }, { status: 500 });
  }

  if (auth === 'login') {
    const user = findUserByEmail(email);
    if (!user) return NextResponse.json({ msg: '用户不存在' }, { status: 401 });
    if (encrypt(pwd) !== user.pwdHash) return NextResponse.json({ msg: '密码不正确' }, { status: 401 });

    const token = jsonwebtoken.sign({ email: user.email, role: user.role }, jwtSecret, { expiresIn: '3d' });
    cookies().set('token', token, { httpOnly: true, expires: new Date(Date.now() + threeDays) });
    return NextResponse.json({ data: { email: user.email }, msg: '登录成功' });
  }

  if (auth === 'register') {
    if (findUserByEmail(email)) return NextResponse.json({ msg: '用户已存在' }, { status: 400 });
    const newUser = addUser(email, pwd);
    const token = jsonwebtoken.sign({ email: newUser.email, role: newUser.role }, jwtSecret, { expiresIn: '3d' });
    
    cookies().set('token', token, { httpOnly: true, expires: new Date(Date.now() + threeDays) });
    return NextResponse.json({ data: { email: newUser.email }, msg: '注册成功' });
  }

  return NextResponse.json({ msg: '不支持的操作' }, { status: 400 });
}

// 新增 OPTIONS 方法，解决预检请求 405 核心问题
export async function OPTIONS() {
  return NextResponse.json({}, { status: 200 });
}
