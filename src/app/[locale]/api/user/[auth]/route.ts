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

  if (auth === 'login') {
    const user = findUserByEmail(email);
    if (!user) return NextResponse.json({ msg: '用户不存在' }, { status: 401 });

    if (encrypt(pwd) !== user.pwdHash) {
      return NextResponse.json({ msg: '密码不正确' }, { status: 401 });
    }

    const info = { email: user.email, role: user.role };
    const token = jsonwebtoken.sign(info, process.env.JWT_SECRET || '', { expiresIn: '3d' });
    const oneDay = 3 * 24 * 60 * 60 * 1000;
    cookies().set('token', token, { httpOnly: true, expires: Date.now() + oneDay });

    return NextResponse.json({ data: { email: user.email }, msg: '登录成功' });
  }

  if (auth === 'register') {
    const exists = findUserByEmail(email);
    if (exists) return NextResponse.json({ msg: '用户已存在' }, { status: 400 });

    const newUser = addUser(email, pwd);
    const info = { email: newUser.email, role: newUser.role };
    const token = jsonwebtoken.sign(info, process.env.JWT_SECRET || '', { expiresIn: '3d' });
    const oneDay = 3 * 24 * 60 * 60 * 1000;
    cookies().set('token', token, { httpOnly: true, expires: Date.now() + oneDay });

    return NextResponse.json({ data: { email: newUser.email }, msg: '注册成功' });
  }

  return NextResponse.json({ msg: '不支持的操作' }, { status: 400 });
}    }
    const newUser = addUser(email, pwd);
    const info = { email: newUser.email, role: newUser.role };
    const token = jsonwebtoken.sign(info, process.env.JWT_SECRET || '', { expiresIn: '3d' });
    const oneDay = 3 * 24 * 60 * 60 * 1000;
    cookies().set('token', token, { httpOnly: true, expires: Date.now() + oneDay });

    return NextResponse.json({ data: { email: newUser.email }, msg: '注册成功' });
  }

  return NextResponse.json({ msg: '不支持的操作' }, { status: 400 });
}
