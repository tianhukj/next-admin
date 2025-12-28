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
  // 修复点1：提前定义 3天有效期 常量，避免重复写，精简代码
  const threeDays = 3 * 24 * 60 * 60 * 1000;
  // 修复点2：提前获取并校验 JWT_SECRET，避免签名失败，同时抛错更清晰
  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) {
    return NextResponse.json({ msg: '服务端配置异常' }, { status: 500 });
  }

  if (auth === 'login') {
    const user = findUserByEmail(email);
    if (!user) return NextResponse.json({ msg: '用户不存在' }, { status: 401 });

    if (encrypt(pwd) !== user.pwdHash) {
      return NextResponse.json({ msg: '密码不正确' }, { status: 401 });
    }

    const info = { email: user.email, role: user.role };
    // 修复点3：用校验后的 jwtSecret，移除 || '' 避免空密钥签名
    const token = jsonwebtoken.sign(info, jwtSecret, { expiresIn: '3d' });
    // 修复点4：expires 改为 Date 实例（原代码是数字，Next.js 不兼容）
    cookies().set('token', token, { httpOnly: true, expires: new Date(Date.now() + threeDays) });

    return NextResponse.json({ data: { email: user.email }, msg: '登录成功' });
  }

  if (auth === 'register') {
    const exists = findUserByEmail(email);
    if (exists) return NextResponse.json({ msg: '用户已存在' }, { status: 400 });

    const newUser = addUser(email, pwd);
    const info = { email: newUser.email, role: newUser.role };
    // 修复点3 同步：用校验后的 jwtSecret 签名
    const token = jsonwebtoken.sign(info, jwtSecret, { expiresIn: '3d' });
    // 修复点4 同步：expires 改为 Date 实例
    cookies().set('token', token, { httpOnly: true, expires: new Date(Date.now() + threeDays) });

    return NextResponse.json({ data: { email: newUser.email }, msg: '注册成功' });
  }

  return NextResponse.json({ msg: '不支持的操作' }, { status: 400 });
}
    cookies().set('token', token, { httpOnly: true, expires: Date.now() + oneDay });

    return NextResponse.json({ data: { email: newUser.email }, msg: '注册成功' });
  }

  return NextResponse.json({ msg: '不支持的操作' }, { status: 400 });
}
    cookies().set('token', token, { httpOnly: true, expires: Date.now() + oneDay });

    return NextResponse.json({ data: { email: newUser.email }, msg: '注册成功' });
  }

  return NextResponse.json({ msg: '不支持的操作' }, { status: 400 });
}
